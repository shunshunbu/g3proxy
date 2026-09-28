use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() {
    let icap_server = "127.0.0.1:1344";
    let service = "echo";
    let total_bytes: usize = 12 * 1024 * 1024;
    let chunk_size: usize = 256 * 1024;

    println!("ICAP performance test");
    println!("Server: {}", icap_server);
    println!("Service: {}", service);
    println!("Total data: {} MB", total_bytes / 1024 / 1024);
    println!("Chunk size: {} KB", chunk_size / 1024);
    println!();

    println!("=== Test 1: Single 12MB request ===");
    match test_single_request(icap_server, service, total_bytes, chunk_size).await {
        Ok(duration) => {
            let mbps = (total_bytes as f64 / 1024.0 / 1024.0) / duration.as_secs_f64();
            println!("Duration: {:.2?}", duration);
            println!("Throughput: {:.2} MB/s", mbps);
        }
        Err(e) => println!("Error: {}", e),
    }
    println!();

    println!("=== Test 2: 10 x 1MB requests ===");
    let mut total_duration = std::time::Duration::ZERO;
    let mut success = 0;
    for i in 0..10 {
        match test_single_request(icap_server, service, 1024 * 1024, chunk_size).await {
            Ok(duration) => {
                total_duration += duration;
                success += 1;
                let mbps = 1.0 / duration.as_secs_f64();
                println!("  Request {}: {:.2?}, {:.2} MB/s", i + 1, duration, mbps);
            }
            Err(e) => println!("  Request {}: Error: {}", i + 1, e),
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    if success > 0 {
        let avg = total_duration / success;
        let mbps = (success as f64 * 1.0) / total_duration.as_secs_f64();
        println!("Average: {:.2?}, {:.2} MB/s", avg, mbps);
    }
}

async fn test_single_request(
    server: &str,
    service: &str,
    total_bytes: usize,
    chunk_size: usize,
) -> Result<std::time::Duration, String> {
    let mut stream = TcpStream::connect(server)
        .await
        .map_err(|e| format!("connect failed: {}", e))?;

    let icap_header = format!(
        "REQMOD icap://{}/{} ICAP/1.0\r\n\
         Host: {}\r\n\
         Encapsulated: req-hdr=0, req-body=170\r\n\
         Allow: 204\r\n\
         \r\n",
        server, service, server
    );

    let http_header = "POST /upload/test.bin HTTP/1.1\r\n\
         Host: example.com\r\n\
         Content-Type: application/octet-stream\r\n\
         Transfer-Encoding: chunked\r\n\
         \r\n";

    stream
        .write_all(icap_header.as_bytes())
        .await
        .map_err(|e| format!("write icap header failed: {}", e))?;
    stream
        .write_all(http_header.as_bytes())
        .await
        .map_err(|e| format!("write http header failed: {}", e))?;
    stream.flush().await.map_err(|e| format!("flush failed: {}", e))?;

    let start = Instant::now();

    let mut remaining = total_bytes;
    let buf = vec![0x41u8; chunk_size];

    while remaining > 0 {
        let this_chunk = remaining.min(chunk_size);
        let chunk_header = format!("{:x}\r\n", this_chunk);
        stream
            .write_all(chunk_header.as_bytes())
            .await
            .map_err(|e| format!("write chunk header failed: {}", e))?;
        stream
            .write_all(&buf[..this_chunk])
            .await
            .map_err(|e| format!("write chunk body failed: {}", e))?;
        stream
            .write_all(b"\r\n")
            .await
            .map_err(|e| format!("write chunk trailer failed: {}", e))?;
        stream.flush().await.map_err(|e| format!("flush chunk failed: {}", e))?;
        remaining -= this_chunk;
    }

    stream
        .write_all(b"0\r\n\r\n")
        .await
        .map_err(|e| format!("write terminator failed: {}", e))?;
    stream.flush().await.map_err(|e| format!("flush terminator failed: {}", e))?;

    let mut response_buf = vec![0u8; 4096];
    let mut total_read = 0;

    loop {
        match tokio::time::timeout(
            std::time::Duration::from_secs(60),
            stream.read(&mut response_buf[total_read..]),
        )
        .await
        {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                total_read += n;
                if total_read >= 4 {
                    let end = &response_buf[total_read - 4..total_read];
                    if end == b"\r\n\r\n" {
                        break;
                    }
                }
            }
            Ok(Err(e)) => return Err(format!("read response failed: {}", e)),
            Err(_) => return Err("response timeout (60s)".to_string()),
        }
    }

    let duration = start.elapsed();
    let response_str = String::from_utf8_lossy(&response_buf[..total_read.min(500)]);
    println!("  Response: {}", response_str.lines().next().unwrap_or(""));

    Ok(duration)
}
