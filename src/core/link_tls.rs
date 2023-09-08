use crate::core::link::link_options_for_listener;

use super::{
    link::{link_info_for, LinkDial, LinkInfo, LinkOptions, Links},
    link_tcp::tcp_id_for,
    Core,
};
use ironwood_rs::{encrypted::crypto::to_box_priv, types::Conn};
use log::info;
use openssl::{
    bn,
    pkey::{self, PKey},
    x509::{
        extension::{ExtendedKeyUsage, KeyUsage},
        X509Builder, X509,
    },
};
use std::{error::Error, net::SocketAddr, str::FromStr, sync::Arc};
use tokio::net::{TcpListener, TcpStream};
use tokio_native_tls::{
    native_tls::{self, Identity},
    TlsAcceptor, TlsConnector, TlsStream,
};
use tokio_stream::{wrappers::TcpListenerStream, StreamExt};

#[derive(Clone)]
pub struct LinkTLS {
    pub links: Links,
}

impl LinkTLS {
    pub async fn dial(
        &self,
        core: Arc<Core>,
        url: &url::Url,
        options: LinkOptions,
        sintf: &str,
        sni: &str,
    ) -> Result<(), Box<dyn Error>> {
        let addr = url.host_str().unwrap().to_string()
            + ":"
            + &url.port_or_known_default().unwrap().to_string();
        let addr = SocketAddr::from_str(&addr)?;
        let tcp_conn = TcpStream::connect(addr).await?;
        let info = link_info_for("tls", sintf, &tcp_id_for(&tcp_conn.local_addr()?, &addr));
        if self.links.is_connected_to(&info) {
            return Ok(());
        }
        let conn: tokio_native_tls::native_tls::TlsConnector =
            tokio_native_tls::native_tls::TlsConnector::builder()
                .use_sni(!sni.is_empty())
                .min_protocol_version(Some(tokio_native_tls::native_tls::Protocol::Tlsv12))
                .danger_accept_invalid_certs(true)
                .build()?;
        let conn = TlsConnector::from(conn);
        let conn = conn.connect(sni, tcp_conn).await?;
        if let Ok(Some(peer_cert)) = conn.get_ref().peer_certificate() {
            info!(
                "Peer certificate: {}",
                String::from_utf8_lossy(
                    &X509::from_der(&peer_cert.to_der().unwrap())
                        .unwrap()
                        .to_text()
                        .unwrap()
                )
            );
        }

        let name = url.to_string();
        let name = name.split('?').next().unwrap().trim_end_matches('/');
        let dial = LinkDial {
            url: url.clone(),
            sintf: sintf.to_string(),
        };

        self.handler(
            core,
            dial,
            name.to_string(),
            info.clone(),
            conn,
            options,
            false,
            false,
        )
        .await?;

        Ok(())
    }

    pub async fn listen(
        &self,
        core: Arc<Core>,
        url: &url::Url,
        sintf: &str,
    ) -> Result<(), Box<dyn Error>> {
        let addr = url.host_str().unwrap().to_string()
            + ":"
            + &url.port_or_known_default().unwrap().to_string();
        let addr: SocketAddr = SocketAddr::from_str(&addr)?;
        let listener = TcpListener::bind(addr).await?;
        let (cert, key) = generate_config(core.clone())?;
        let identity = Identity::from_pkcs8(&cert.to_pem()?, &key.private_key_to_pem_pkcs8()?)?;
        let tls_accpetor: TlsAcceptor = native_tls::TlsAcceptor::builder(identity)
            .min_protocol_version(Some(native_tls::Protocol::Tlsv10))
            .build()?
            .into();

        info!("TLS listener started on {}", listener.local_addr()?);
        let mut listener = TcpListenerStream::new(listener);

        let link = self.clone();
        let sintf = sintf.to_string();
        let url = url.clone();
        tokio::spawn(async move {
            while let Some(Ok(conn)) = listener.next().await {
                let info = link_info_for(
                    "tls",
                    &sintf,
                    &tcp_id_for(
                        &conn.local_addr().map_err(|e| e.to_string())?,
                        &conn.peer_addr().map_err(|e| e.to_string())?,
                    ),
                );
                if link.links.is_connected_to(&info) {
                    continue;
                }
                let dial = LinkDial {
                    url: url.clone(),
                    sintf: sintf.to_string(),
                };
                if let Ok(conn) = tls_accpetor.accept(conn).await {
                    link.handler(
                        core.clone(),
                        dial,
                        "tls://".to_string()
                            + &conn.peer_addr().map_err(|e| e.to_string())?.to_string(),
                        info.clone(),
                        conn,
                        link_options_for_listener(&url),
                        true,
                        false,
                    )
                    .await;
                }
            }
            info!(
                "TCP listener stopped on {}",
                listener.into_inner().local_addr().unwrap()
            );
            Result::<(), Box<String>>::Ok(())
        });
        Ok(())
    }

    async fn handler(
        &self,
        core: Arc<Core>,
        dial: LinkDial,
        name: String,
        info: LinkInfo,
        conn: TlsStream<TcpStream>,
        options: LinkOptions,
        incoming: bool,
        force: bool,
    ) -> Result<(), Box<dyn Error>> {
        self.links
            .create(
                core, conn,     // connection
                dial,     // connection URL
                name,     // connection name
                info,     // connection info
                incoming, // not incoming
                force,    // not forced
                options,  // connection options
            )
            .await
    }
}

fn generate_config(core: Arc<Core>) -> Result<(X509, PKey<pkey::Private>), Box<dyn Error>> {
    // Generate a self-signed certificate
    let mut x509_builder = X509Builder::new()?;
    x509_builder.set_version(2)?;
    x509_builder.set_serial_number(bn::BigNum::from_u32(1)?.to_asn1_integer()?.as_ref())?;
    let mut x509_name = openssl::x509::X509NameBuilder::new()?;
    x509_name.append_entry_by_text("CN", &hex::encode(core.public.as_bytes()))?;
    x509_builder.set_subject_name(&x509_name.build())?;
    x509_builder.set_not_before(openssl::asn1::Asn1Time::days_from_now(0)?.as_ref())?;
    x509_builder.set_not_after(openssl::asn1::Asn1Time::days_from_now(365)?.as_ref())?;
    x509_builder.append_extension(
        KeyUsage::new()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;
    x509_builder.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;
    let pr_key = to_box_priv(&core.secret);
    let pu_key = PKey::public_key_from_raw_bytes(core.public.as_bytes(), pkey::Id::ED25519)?;
    let pr_key = PKey::private_key_from_raw_bytes(&pr_key.0, pkey::Id::ED25519)?;
    x509_builder.set_pubkey(&pu_key)?;
    x509_builder.sign(&pr_key, openssl::hash::MessageDigest::null())?;
    let cert = x509_builder.build();
    info!(
        "Generated Certificate: \n{}",
        String::from_utf8_lossy(&cert.to_text()?)
    );

    Ok((cert, pr_key))
}
