extern crate core;

use aucpace::{
    AuCPaceClient, AuCPaceServer, ClientMessage, Database, Error, Result, ServerMessage,
};
use curve25519_dalek::ristretto::RistrettoPoint;
use password_hash::{ParamsString, SaltString};
use rand_core::OsRng;
use scrypt::{Params, Scrypt};
use sha2::Sha512;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::thread;

fn main() -> Result<()> {
    // example username and password, never user these...
    const USERNAME: &'static [u8] = b"jlpicard_1701";
    const PASSWORD: &'static [u8] = b"g04tEd_c4pT41N";

    // the server socket address to bind to
    const SERVER_SOCKET: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 25519);

    // register the user in the database
    let mut base_client: AuCPaceClient<Sha512, OsRng, 16> = AuCPaceClient::new(OsRng);
    let mut database: SingleUserDatabase = Default::default();

    let params = scrypt::Params::recommended();
    let hasher = scrypt::Scrypt;
    base_client.register(USERNAME, PASSWORD, params, hasher)?;

    // spawn a thread for the server
    let server_thread = thread::spawn(move || {
        let listener = TcpListener::bind(SERVER_SOCKET).unwrap();
        let (mut stream, client_addr) = listener.accept().unwrap();

        // wrappers for sending and receiving messages
        let mut send_message = move |message| {
            let serialised = bincode::serialize(message).unwrap();
            stream.write_all(&serialised).unwrap();
        };
        let mut recv_message = move || {
            let mut buf = [0u8; 1024];
            let bytes_received = stream.read(&mut buf).unwrap();
            let received = &buf[..bytes_received];
            let client_message = bincode::deserialize(received).unwrap();
            (buf, client_message)
        };

        let mut base_server: AuCPaceServer<Sha512, OsRng, 16> = AuCPaceServer::new(OsRng);

        // ===== SSID Establishment =====
        let (server, message) = base_server.begin();
        send_message(&message);

        let (_received, client_message) = recv_message();
        let server = if let ClientMessage::ClientNonce(client_nonce) = client_message {
            server.agree_ssid(client_nonce)
        } else {
            panic!("Received invalid client message {:?}", client_message);
        };

        // ===== Augmentation Layer =====
        let (_received, client_message) = recv_message();
        let (server, message) = if let ClientMessage::Username(username) = client_message {
            server.generate_client_info(username, &database, OsRng)
        } else {
            panic!("Received invalid client message {:?}", client_message);
        };
        send_message(&message);

        // ===== CPace substep =====
        let ci = TcpChannelIdentifier::new(client_addr, SERVER_SOCKET).unwrap();
        let (server, message) = server.generate_public_key(ci);
        send_message(&message);

        let (_received, client_message) = recv_message();
        let server = if let ClientMessage::PublicKey(client_pubkey) = client_message {
            server.receive_client_pubkey(client_pubkey)
        } else {
            panic!("Received invalid client message {:?}", client_message);
        };

        // ===== Explicit Mutual Authentication =====
        let (_received, client_message) = recv_message();
        if let ClientMessage::ClientAuthenticator(client_authenticator) = client_message {
            let (key, message) = server.receive_client_authenticator(client_authenticator)?;
            send_message(&message);

            // return the dervied key
            Ok(key)
        } else {
            panic!("Received invalid client message {:?}", client_message);
        }
    });

    // spawn a thread for the client
    let client_thread = thread::spawn(move || {
        let mut stream = TcpStream::connect(SERVER_SOCKET).unwrap();

        // wrappers for sending and receiving messages
        let mut send_message = move |message| {
            let serialised = bincode::serialize(message).unwrap();
            stream.write_all(&serialised).unwrap();
        };
        let mut recv_message = move || {
            let mut read_buf = [0u8; 1024];
            let bytes_received = stream.read(&mut read_buf).unwrap();
            let received = &read_buf[..bytes_received];
            let server_message = bincode::deserialize(received).unwrap();
            (received, server_message)
        };

        // ===== SSID ESTABLISHMENT =====
        let (client, message) = base_client.begin();
        send_message(&message);

        // receive the server nonce to agree on SSID
        let (_received, server_message) = recv_message();
        let client = if let ServerMessage::ServerNonce(server_nonce) = server_message {
            client.agree_ssid(server_nonce)
        } else {
            panic!("Received invalid server message {:?}", server_message);
        };

        // ===== Augmentation Layer =====
        let (client, message) = client.start_augmentation(USERNAME);
        send_message(&message);

        let (_received, server_message) = recv_message();
        let client = if let ServerMessage::AugmentationInfo {
            x_pub,
            salt,
            pbkdf_params,
            ..
        } = server_message
        {
            let params = {
                // its christmas time!
                let log_n = pbkdf_params.get_str("log_n").unwrap().parse().unwrap();
                let r = pbkdf_params.get_str("r").unwrap().parse().unwrap();
                let p = pbkdf_params.get_str("p").unwrap().parse().unwrap();

                Params::new(log_n, r, p).unwrap()
            };
            client.generate_cpace(x_pub, PASSWORD, &salt, params, Scrypt)?
        } else {
            panic!("Received invalid server message {:?}", server_message);
        };

        // ===== CPace substep =====
        let ci = TcpChannelIdentifier::new(stream.local_addr().unwrap(), SERVER_SOCKET).unwrap();
        let (client, message) = client.generate_public_key(ci, &mut OsRng);
        send_message(&message);

        let (_received, server_message) = recv_message();
        let (client, message) = if let ServerMessage::PublicKey(server_pubkey) = server_message {
            client.receive_server_pubkey(server_pubkey)
        } else {
            panic!("Received invalid server message {:?}", server_message);
        };

        // ===== Explicit Mutual Auth =====
        send_message(&message);

        let (_received, server_message) = recv_message();
        if let ServerMessage::ServerAuthenticator(server_authenticator) = server_message {
            client.receive_server_authenticator(server_authenticator)
        } else {
            panic!("Received invalid server message {:?}", server_message);
        }
    });

    // assert that both threads arrived at the same key
    assert_eq!(client_thread.join().unwrap(), server_thread.join().unwrap());

    Ok(())
}

/// Password Verifier database which can store the info for one user
#[derive(Debug, Default)]
struct SingleUserDatabase {
    user: Option<Vec<u8>>,
    data: Option<(RistrettoPoint, SaltString, ParamsString)>,
}

impl Database for SingleUserDatabase {
    type PasswordVerifier = RistrettoPoint;

    fn lookup_verifier(
        &self,
        username: &[u8],
    ) -> Option<(Self::PasswordVerifier, SaltString, ParamsString)> {
        match &self.user {
            Some(stored_username) if stored_username == username => self.data.clone(),
            _ => None,
        }
    }

    fn store_verifier(
        &mut self,
        username: &[u8],
        salt: SaltString,
        _uad: Option<&[u8]>,
        verifier: Self::PasswordVerifier,
        params: ParamsString,
    ) {
        self.user = Some(username.to_vec());
        self.data = Some((verifier, salt, params));
    }
}

/// Channel Identifier type for TCP connections
struct TcpChannelIdentifier {
    // src.ip:src.port:dst.ip:dst.port
    id: Vec<u8>,
}

impl TcpChannelIdentifier {
    fn new(src: SocketAddr, dst: SocketAddr) -> std::io::Result<Self> {
        let mut id = vec![];

        // write src.ip:src.port:dst.ip:dst.port
        match src.ip() {
            IpAddr::V4(addr) => id.write(&addr.octets()),
            IpAddr::V6(addr) => id.write(&addr.octets()),
        }?;
        id.push(b':');
        id.write(&src.port().to_be_bytes());
        id.push(b':');
        match dst.ip() {
            IpAddr::V4(addr) => id.write(&addr.octets()),
            IpAddr::V6(addr) => id.write(&addr.octets()),
        }?;
        id.push(b':');
        id.write(&dst.port().to_be_bytes());

        Ok(Self { id })
    }
}

impl AsRef<[u8]> for TcpChannelIdentifier {
    fn as_ref(&self) -> &[u8] {
        &self.id
    }
}
