//! Read the ClientHello before choosing an interception policy or certificate.
use std::io;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader};
use tokio_rustls::StartHandshake;

// Bound both the TLS parser's input and the copy retained for a possible tunnel.
const MAX_CLIENT_HELLO_BYTES: usize = 64 * 1024;
pub(super) const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub(super) async fn read_client_hello<IO>(
    mut stream: BufReader<IO>,
) -> io::Result<(StartHandshake<BufReader<IO>>, Vec<u8>)>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut acceptor = rustls::server::Acceptor::default();
    let mut prefix = Vec::new();
    loop {
        let remaining = MAX_CLIENT_HELLO_BYTES - prefix.len();
        if remaining == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ClientHello too large",
            ));
        }
        let buffered = stream.fill_buf().await?;
        let available = &buffered[..buffered.len().min(remaining)];
        let consumed = acceptor.read_tls(&mut &available[..])?;
        if consumed == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        prefix.extend_from_slice(&available[..consumed]);
        stream.consume(consumed);
        match acceptor.accept() {
            Ok(Some(accepted)) => {
                // rustls retains the parsed handshake for interception. For a
                // bypass, replay exactly the consumed TLS bytes, then drain
                // BufReader (including hyper's CONNECT read-ahead) normally.
                return Ok((StartHandshake::from_parts(accepted, stream), prefix));
            }
            Ok(None) => {} // TCP and TLS-record fragmentation are both valid.
            Err((error, _alert)) => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, error));
            }
        }
    }
}
