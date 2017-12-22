/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2017 Zetok Zalbavar <zexavexxe@gmail.com>
    Copyright © 2017 Roman Proskuryakov <humbug@deeptown.org>

    This file is part of Tox.

    Tox is libre software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
*/

extern crate tox;
extern crate futures;
extern crate bytes;
extern crate nom;
extern crate tokio_core;
extern crate tokio_io;

use tox::toxcore::crypto_core::*;
use tox::toxcore::tcp::*;
use tox::toxcore::tcp::packet::*;
use tox::toxcore::tcp::codec;

use std::collections::HashMap;
use std::cell::RefCell;
use std::rc::Rc;

use futures::{Sink, Stream, Future, future, stream};
use futures::sync::mpsc;

use tokio_io::*;
use tokio_core::reactor::Core;
use tokio_core::net::TcpListener;

use tox::toxcore::tcp::server::client::Client;

#[derive(Clone)]
struct Server {
    connected_clients: Rc<RefCell<HashMap<PublicKey, Client>>>,
}

impl Server {
    fn new() -> Server {
        Server {
            connected_clients: Rc::new(RefCell::new(HashMap::new()))
        }
    }
    /** Insert the client into connected_clients. Do nothing else.
    */
    fn insert(&self, client: Client) {
        self.connected_clients.borrow_mut()
            .insert(client.pk(), client);
    }
    fn handle_route_request(&self, pk: &PublicKey, packet: RouteRequest) -> IoFuture<()> {
        let index = {
            // check if client was already linked to pk
            let mut clients = self.connected_clients.borrow_mut();
            if let Some(client) = clients.get_mut(pk) {
                if pk == &packet.peer_pk {
                    // send RouteResponse(0) if client requests its own pk
                    return client.send_route_response(pk, 0)
                }
                let index = client.get_connection_id(&packet.peer_pk);
                if let Some(index) = index {
                    // send RouteResponse(index + 16) if client was already linked to pk
                    return client.send_route_response(&packet.peer_pk, index + 16)
                } else {
                    // try to insert new link into client.links
                    let index = client.insert_connection_id(&packet.peer_pk);
                    if let Some(index) = index {
                        index
                    } else {
                        // send RouteResponse(0) if no space to insert new link
                        return client.send_route_response(&packet.peer_pk, 0)
                    }
                }
            } else {
                return Box::new( future::err(
                    std::io::Error::new(std::io::ErrorKind::Other,
                        "RouteRequest: no such PK"
                )))
            }
        };
        let clients = self.connected_clients.borrow();
        let client = clients.get(pk).unwrap(); // can not fail
        if let Some(other_client) = clients.get(&packet.peer_pk) {
            // check if current pk is linked inside other_client
            let other_index = other_client.get_connection_id(pk);
            if let Some(other_index) = other_index {
                // the are both linked, send RouteResponse and
                // send each other ConnectNotification
                // we don't care if connect notifications fail
                let current_notification = client.send_connect_notification(index + 16);
                let other_notification = other_client.send_connect_notification(other_index + 16);
                return Box::new(
                    client.send_route_response(&packet.peer_pk, index + 16)
                        .join(current_notification)
                        .join(other_notification)
                        .map(|_| ())
                )
            } else {
                // they are not linked
                // send RouteResponse(index + 16) only to current client
                client.send_route_response(&packet.peer_pk, index + 16)
            }
        } else {
            // send RouteResponse(index + 16) only to current client
            client.send_route_response(&packet.peer_pk, index + 16)
        }
    }
    fn handle_route_response(&self, _pk: &PublicKey, _packet: RouteResponse) -> IoFuture<()> {
        Box::new(future::err(
            std::io::Error::new(std::io::ErrorKind::Other,
                "Client must not send RouteResponse to server"
        )))
    }
    fn handle_connect_notification(&self, _pk: &PublicKey, _packet: ConnectNotification) -> IoFuture<()> {
        // Although normally a client should not send ConnectNotification to server
        //  we ignore it for backward compatibility
        Box::new(future::ok(()))
    }
    fn handle_disconnect_notification(&self, pk: &PublicKey, packet: DisconnectNotification) -> IoFuture<()> {
        if packet.connection_id < 16 {
            return Box::new( future::err(
                std::io::Error::new(std::io::ErrorKind::Other,
                    "DisconnectNotification.connection_id < 16"
            )))
        }
        let mut clients = self.connected_clients.borrow_mut();
        let other_pk = {
            if let Some(client) = clients.get_mut(pk) {
                // unlink other_pk from client.links if any
                // and return previous value
                let link = client.take_link(packet.connection_id - 16);
                if let Some(other_pk) = link {
                    other_pk
                } else {
                    return Box::new( future::err(
                        std::io::Error::new(std::io::ErrorKind::Other,
                            "DisconnectNotification.connection_id is not linked"
                    )))
                }
            } else {
                return Box::new( future::err(
                    std::io::Error::new(std::io::ErrorKind::Other,
                        "DisconnectNotification: no such PK"
                )))
            }
        };

        if let Some(other_client) = clients.get_mut(&other_pk) {
            let connection_id = other_client.get_connection_id(pk).map(|x| x + 16);
            if let Some(connection_id) = connection_id {
                // unlink pk from other_client it and send notification
                other_client.take_link(connection_id);
                other_client.send_disconnect_notification(connection_id)
            } else {
                // Do nothing because
                // other_client has not sent RouteRequest yet to connect to this client
                Box::new( future::ok(()) )
            }
        } else {
            // other_client is not connected to the server, so ignore it
            Box::new( future::ok(()) )
        }
    }
    fn handle_ping_request(&self, pk: &PublicKey, packet: PingRequest) -> IoFuture<()> {
        if packet.ping_id == 0 {
            return Box::new( future::err(
                std::io::Error::new(std::io::ErrorKind::Other,
                    "PingRequest.ping_id == 0"
            )))
        }
        let clients = self.connected_clients.borrow();
        if let Some(client) = clients.get(pk) {
            client.send_pong_response(packet.ping_id)
        } else {
            Box::new( future::err(
                std::io::Error::new(std::io::ErrorKind::Other,
                    "PingRequest: no such PK"
            )) )
        }
    }
    fn handle_pong_response(&self, pk: &PublicKey, packet: PongResponse) -> IoFuture<()> {
        if packet.ping_id == 0 {
            return Box::new( future::err(
                std::io::Error::new(std::io::ErrorKind::Other,
                    "PongResponse.ping_id == 0"
            )))
        }
        let clients = self.connected_clients.borrow();
        if let Some(client) = clients.get(pk) {
            if packet.ping_id == client.ping_id() {
                Box::new( future::ok(()) )
            } else {
                Box::new( future::err(
                    std::io::Error::new(std::io::ErrorKind::Other, "PongResponse.ping_id does not match")
                ))
            }
        } else {
            return Box::new( future::err(
                std::io::Error::new(std::io::ErrorKind::Other,
                    "PongResponse: no such PK"
            )) )
        }
    }
    fn handle_oob_send(&self, pk: &PublicKey, packet: OobSend) -> IoFuture<()> {
        if packet.data.len() == 0 || packet.data.len() > 1024 {
            return Box::new( future::err(
                std::io::Error::new(std::io::ErrorKind::Other,
                    "OobSend wrong data length"
            )))
        }
        let clients = self.connected_clients.borrow();
        if let Some(other_client) = clients.get(&packet.destination_pk) {
            other_client.send_oob(pk, packet.data)
        } else {
            // Do nothing because there is no other_client connected to server
            Box::new( future::ok(()) )
        }
    }
    fn handle_oob_receive(&self, _pk: &PublicKey, _packet: OobReceive) -> IoFuture<()> {
        Box::new( future::err(
            std::io::Error::new(std::io::ErrorKind::Other,
                "Client must not send OobReceive to server"
        )))
    }
    fn handle_data(&self, pk: &PublicKey, packet: Data) -> IoFuture<()> {
        if packet.connection_id < 16 {
            return Box::new( future::err(
                std::io::Error::new(std::io::ErrorKind::Other,
                    "Data.connection_id < 16"
            )))
        }
        let clients = self.connected_clients.borrow();
        let other_pk = {
            if let Some(client) = clients.get(pk) {
                if let Some(other_pk) = client.get_link(packet.connection_id - 16) {
                    other_pk
                } else {
                    return Box::new( future::err(
                        std::io::Error::new(std::io::ErrorKind::Other,
                            "Data.connection_id is not linked"
                    )))
                }
            } else {
                return Box::new( future::err(
                    std::io::Error::new(std::io::ErrorKind::Other,
                        "Data: no such PK"
                )))
            }
        };
        if let Some(other_client) = clients.get(&other_pk) {
            let connection_id = other_client.get_connection_id(pk).map(|x| x + 16);
            if let Some(connection_id) = connection_id {
                other_client.send_data(connection_id, packet.data)
            } else {
                // Do nothing because
                // other_client has not sent RouteRequest yet to connect to this client
                Box::new( future::ok(()) )
            }
        } else {
            // Do nothing because there is no other_client connected to server
            Box::new( future::ok(()) )
        }
    }
    /**The main processing function. Call in on each incoming packet from connected and
    handshaked client.
    */
    fn handle_packet(&self, pk: &PublicKey, packet: Packet) -> IoFuture<()> {
        match packet {
            Packet::RouteRequest(packet) => self.handle_route_request(pk, packet),
            Packet::RouteResponse(packet) => self.handle_route_response(pk, packet),
            Packet::ConnectNotification(packet) => self.handle_connect_notification(pk, packet),
            Packet::DisconnectNotification(packet) => self.handle_disconnect_notification(pk, packet),
            Packet::PingRequest(packet) => self.handle_ping_request(pk, packet),
            Packet::PongResponse(packet) => self.handle_pong_response(pk, packet),
            Packet::OobSend(packet) => self.handle_oob_send(pk, packet),
            Packet::OobReceive(packet) => self.handle_oob_receive(pk, packet),
            Packet::Data(packet) => self.handle_data(pk, packet),
        }
    }
    /** Gracefully shutdown client by pk. Remove it from the list of connected_clients.
    If there are any clients mutually linked to current client, we send them corresponding
    DisconnectNotification.
    */
    fn shutdown_client(&self, pk: &PublicKey) -> IoFuture<()> {
        let client = if let Some(client) = self.connected_clients.borrow_mut().remove(pk) {
            client
        } else {
            return Box::new( future::err(
                std::io::Error::new(std::io::ErrorKind::Other,
                    "Can'not find client by pk to shutdown it"
            )))
        };
        let notifications = client.iter_links()
            // foreach link that is Some(other_pk)
            .filter_map(|&other_pk| other_pk)
            .map(|other_pk| {
                if let Some(other_client) = self.connected_clients.borrow().get(&other_pk) {
                    // check if current pk is linked in other_pk
                    let other_index = other_client.get_connection_id(pk).map(|x| x + 16);
                    if let Some(other_index) = other_index {
                        // it is linked, we should notify other_client
                        other_client.send_disconnect_notification(other_index)
                    } else {
                        // Current client is not linked in other_pk
                        Box::new( future::ok(()) )
                    }
                } else {
                    // other_client is not connected to the server
                    Box::new( future::ok(()) )
                }
            });
        Box::new( stream::futures_unordered(notifications).for_each(Ok) )
    }
}

fn main() {
    // Some constant keypair
    let server_pk = PublicKey([177, 185, 54, 250, 10, 168, 174,
                            148, 0, 93, 99, 13, 131, 131, 239,
                            193, 129, 141, 80, 158, 50, 133, 100,
                            182, 179, 183, 234, 116, 142, 102, 53, 38]);
    let server_sk = SecretKey([74, 163, 57, 111, 32, 145, 19, 40,
                            44, 145, 233, 210, 173, 67, 88, 217,
                            140, 147, 14, 176, 106, 255, 54, 249,
                            159, 12, 18, 39, 123, 29, 125, 230]);
    let addr = "0.0.0.0:12345".parse().unwrap();
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let listener = TcpListener::bind(&addr, &handle).unwrap();

    println!("Listening on {} using PK {:?}", addr, &server_pk.0);

    let server_inner = Server::new();

    let server = listener.incoming().for_each(|(socket, addr)| {
        println!("A new client connected from {}", addr);

        let server_inner_c = server_inner.clone();
        let register_client = make_server_handshake(socket, server_sk.clone())
            .map_err(|e| {
                println!("handshake error: {}", e);
                e
            })
            .and_then(move |(socket, channel, client_pk)| {
                println!("Handshake for client {:?} complited", &client_pk);
                let (tx, rx) = mpsc::channel(8);
                server_inner_c.insert(Client::new(tx, &client_pk));

                Ok((socket, channel, client_pk, rx))
            });
        let server_inner_c = server_inner.clone();
        let process_connection = register_client
            .and_then(move |(socket, channel, client_pk, rx)| {
                let secure_socket = socket.framed(codec::Codec::new(channel));
                let (to_client, from_client) = secure_socket.split();

                // reader = for each Packet from client process it
                let server_inner_c_c = server_inner_c.clone();
                let reader = from_client.for_each(move |packet| {
                    println!("Handle {:?} => {:?}", client_pk, packet);
                    server_inner_c_c.handle_packet(&client_pk, packet)
                });

                // writer = for each Packet from rx send it to client
                let writer = rx
                    .map_err(|()| unreachable!("rx can't fail"))
                    .fold(to_client, move |to_client, packet| {
                        println!("Send {:?} => {:?}", client_pk, packet);
                        to_client.send(packet)
                    })
                    // drop to_client when rx stream is exhausted
                    .map(|_to_client| ());

                // TODO ping request = each 30s send PingRequest to client

                let server_inner_c_c = server_inner_c.clone();
                reader.select(writer)
                    .map(|_| ())
                    .map_err(move |(err, _select_next)| {
                        println!("Processing client {:?} ended with error: {:?}", &client_pk, err);
                        err
                    })
                    .then(move |r_processing| {
                        println!("shutdown PK {:?}", &client_pk);
                        server_inner_c_c.shutdown_client(&client_pk)
                            .then(move |r_shutdown| r_processing.and(r_shutdown))
                    })
            });
        handle.spawn(process_connection.then(|r| {
            println!("end of processing with result {:?}", r);
            Ok(())
        }));

        Ok(())
    });
    core.run(server).unwrap();
}
