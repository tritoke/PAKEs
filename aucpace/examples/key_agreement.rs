extern crate core;

use aucpace::{AuCPaceClient, AuCPaceServer, ClientMessage, Database, Result, ServerMessage};
use curve25519_dalek::ristretto::RistrettoPoint;
use password_hash::{ParamsString, SaltString};
use rand_core::OsRng;
use scrypt::{Params, Scrypt};
use sha2::digest::Output;
use sha2::Sha512;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::thread;

fn main() -> Result<()> {
    // example username and password, never user these...
    const USERNAME: &'static [u8] = b"jlpicard_1701";
    const PASSWORD: &'static [u8] = b"g04tEd_c4pT41N";

    // the server socket address to bind to
    let server_socket: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 25519);

    // register the user in the database
    let mut base_client: AuCPaceClient<Sha512, OsRng, 16> = AuCPaceClient::new(OsRng);
    let mut database: SingleUserDatabase = Default::default();

    let params = Params::recommended();
    let registration = base_client.register(USERNAME, PASSWORD, params, Scrypt)?;
    if let ClientMessage::Registration {
        username,
        salt,
        params,
        verifier,
    } = registration
    {
        database.store_verifier(username, salt, None, verifier, params);
    }

    // spawn a thread for the server
    let server_thread = thread::spawn(move || -> Result<Output<Sha512>> {
        let listener = TcpListener::bind(server_socket).unwrap();
        let (mut stream, client_addr) = listener.accept().unwrap();

        // buffer for receiving packets
        let mut buf = [0u8; 1024];

        let mut base_server: AuCPaceServer<Sha512, OsRng, 16> = AuCPaceServer::new(OsRng);

        // ===== SSID Establishment =====
        let (server, message) = base_server.begin();
        println!("[server] Sending message: ServerNonce");
        stream
            .write_all(&bincode::serialize(&message).unwrap())
            .unwrap();

        let mut bytes_received = stream.read(&mut buf).unwrap();
        let mut received = &buf[..bytes_received];
        let mut client_message: ClientMessage<16> = bincode::deserialize(received).unwrap();

        let server = if let ClientMessage::ClientNonce(client_nonce) = client_message {
            server.agree_ssid(client_nonce)
        } else {
            panic!("Received invalid client message {:?}", client_message);
        };

        // ===== Augmentation Layer =====
        bytes_received = stream.read(&mut buf).unwrap();
        received = &buf[..bytes_received];
        client_message = bincode::deserialize(received).unwrap();

        let (server, message) = if let ClientMessage::Username(username) = client_message {
            server.generate_client_info(username, &database, OsRng)
        } else {
            panic!("Received invalid client message {:?}", client_message);
        };
        println!("[server] Sending message: AugmentationInfo");
        stream
            .write_all(&bincode::serialize(&message).unwrap())
            .unwrap();

        // ===== CPace substep =====
        let ci = TcpChannelIdentifier::new(client_addr, server_socket).unwrap();
        let (server, message) = server.generate_public_key(ci);
        println!("[server] Sending message: PublicKey");
        stream
            .write_all(&bincode::serialize(&message).unwrap())
            .unwrap();

        bytes_received = stream.read(&mut buf).unwrap();
        received = &buf[..bytes_received];
        client_message = bincode::deserialize(received).unwrap();

        let server = if let ClientMessage::PublicKey(client_pubkey) = client_message {
            server.receive_client_pubkey(client_pubkey)
        } else {
            panic!("Received invalid client message {:?}", client_message);
        };

        // ===== Explicit Mutual Authentication =====
        bytes_received = stream.read(&mut buf).unwrap();
        received = &buf[..bytes_received];
        client_message = bincode::deserialize(received).unwrap();

        if let ClientMessage::ClientAuthenticator(client_authenticator) = client_message {
            let (key, message) = server.receive_client_authenticator(client_authenticator)?;
            println!("[server] Sending message: ServerAuthenticator");
            stream
                .write_all(&bincode::serialize(&message).unwrap())
                .unwrap();

            // return the dervied key
            Ok(key)
        } else {
            panic!("Received invalid client message {:?}", client_message);
        }
    });

    // spawn a thread for the client
    let client_thread = thread::spawn(move || -> Result<Output<Sha512>> {
        let mut stream = TcpStream::connect(server_socket).unwrap();

        // wrappers for sending and receiving messages
        let mut buf = [0u8; 1024];

        // ===== SSID ESTABLISHMENT =====
        let (client, message) = base_client.begin();
        println!("[client] Sending message: ClientNonce");
        stream
            .write_all(&bincode::serialize(&message).unwrap())
            .unwrap();

        // receive the server nonce to agree on SSID
        let mut bytes_received = stream.read(&mut buf).unwrap();
        let mut received = &buf[..bytes_received];
        let mut server_message: ServerMessage<16> = bincode::deserialize(received).unwrap();
        let client = if let ServerMessage::ServerNonce(server_nonce) = server_message {
            client.agree_ssid(server_nonce)
        } else {
            panic!("Received invalid server message {:?}", server_message);
        };

        // ===== Augmentation Layer =====
        let (client, message) = client.start_augmentation(USERNAME);
        println!("[client] Sending message: Username");
        stream
            .write_all(&bincode::serialize(&message).unwrap())
            .unwrap();

        bytes_received = stream.read(&mut buf).unwrap();
        received = &buf[..bytes_received];
        server_message = bincode::deserialize(received).unwrap();

        let client = if let ServerMessage::AugmentationInfo {
            x_pub,
            salt,
            pbkdf_params,
            ..
        } = server_message
        {
            let params = {
                // its christmas time!
                let log_n = pbkdf_params.get_str("ln").unwrap().parse().unwrap();
                let r = pbkdf_params.get_str("r").unwrap().parse().unwrap();
                let p = pbkdf_params.get_str("p").unwrap().parse().unwrap();

                Params::new(log_n, r, p).unwrap()
            };
            client.generate_cpace(x_pub, PASSWORD, &salt, params, Scrypt)?
        } else {
            panic!("Received invalid server message {:?}", server_message);
        };

        // ===== CPace substep =====
        let ci = TcpChannelIdentifier::new(stream.local_addr().unwrap(), server_socket).unwrap();
        let (client, message) = client.generate_public_key(ci, &mut OsRng);
        println!("[client] Sending message: PublicKey");
        stream
            .write_all(&bincode::serialize(&message).unwrap())
            .unwrap();

        bytes_received = stream.read(&mut buf).unwrap();
        received = &buf[..bytes_received];
        server_message = bincode::deserialize(received).unwrap();
        let (client, message) = if let ServerMessage::PublicKey(server_pubkey) = server_message {
            client.receive_server_pubkey(server_pubkey)
        } else {
            panic!("Received invalid server message {:?}", server_message);
        };

        // ===== Explicit Mutual Auth =====
        println!("[client] Sending message: ClientAuthenticator");
        stream
            .write_all(&bincode::serialize(&message).unwrap())
            .unwrap();

        bytes_received = stream.read(&mut buf).unwrap();
        received = &buf[..bytes_received];
        server_message = bincode::deserialize(received).unwrap();
        if let ServerMessage::ServerAuthenticator(server_authenticator) = server_message {
            client.receive_server_authenticator(server_authenticator)
        } else {
            panic!("Received invalid server message {:?}", server_message);
        }
    });

    // assert that both threads arrived at the same key
    let client_key: Output<Sha512> = client_thread.join().unwrap().unwrap();
    let server_key: Output<Sha512> = server_thread.join().unwrap().unwrap();
    assert_eq!(client_key, server_key);
    println!(
        "Negotiation finished, both parties arrived at a key of: {:X}",
        client_key
    );

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
        id.write(&src.port().to_be_bytes())?;
        id.push(b':');
        match dst.ip() {
            IpAddr::V4(addr) => id.write(&addr.octets()),
            IpAddr::V6(addr) => id.write(&addr.octets()),
        }?;
        id.push(b':');
        id.write(&dst.port().to_be_bytes())?;

        Ok(Self { id })
    }
}

impl AsRef<[u8]> for TcpChannelIdentifier {
    fn as_ref(&self) -> &[u8] {
        &self.id
    }
}
