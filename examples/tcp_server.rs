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

#[macro_use] extern crate log;

use tox::toxcore::crypto_core::*;
use tox::toxcore::tcp::*;
use tox::toxcore::tcp::packet::*;
use tox::toxcore::tcp::codec;

use std::collections::HashMap;
use std::cell::RefCell;
use std::rc::Rc;

use futures::{Sink, Stream, Future, future};
use futures::sync::mpsc;

use tokio_io::*;
use tokio_core::reactor::Core;
use tokio_core::net::TcpListener;

#[derive(Clone)]
struct Client {
    pk: PublicKey,
    tx: mpsc::Sender<Packet>,
    links: [Option<PublicKey>; 240],
    ping_id: u64
}

impl Client {
    fn new(tx: mpsc::Sender<Packet>, pk: &PublicKey) -> Client {
        Client {
            pk: *pk,
            tx: tx,
            links: [None; 240],
            ping_id: 0
        }
    }
    /// Some(index) if link exists
    /// None if no links
    fn get_connection_id(&self, to: &PublicKey) -> Option<u8> {
        unimplemented!()
    }
    /// Some(index) if has been inserted or link existed
    /// None if no free space to insert
    fn insert_connection_id(&mut self, to: &PublicKey) -> Option<u8> {
        match self.get_connection_id(to) {
            Some(index) => Some(index),
            None => {
                unimplemented!()
            }
        }
    }
    fn send_impl(&self, packet: Packet) -> IoFuture<()> {
        Box::new(self.tx.clone() // clone tx sender for 1 send only
            .send(packet)
            .map(|_tx| ()) // ignore tx because it was cloned
            .map_err(|_| {
                // This may only happen if rx is gone
                // So cast SendError<T> to a corresponding std::io::Error
                std::io::Error::from(std::io::ErrorKind::UnexpectedEof)
            })
        )
    }
    fn send(&self, packet: Packet) -> IoFuture<()> {
        Box::new(self.send_impl(packet)
            .map_err(|e| {
                debug!("send: {:?}", e);
                e
            })
        )
    }
    fn send_ignore_error(&self, packet: Packet) -> IoFuture<()> {
        Box::new(self.send_impl(packet)
            .then(|e| {
                debug!("send_ignore_error: {:?}", e);
                Ok(()) // ignore if somehow failed to send it
            })
        )
    }
    fn send_route_response(&self, pk: &PublicKey, connection_id: u8) -> IoFuture<()> {
        self.send(
            Packet::RouteResponse(RouteResponse {
                connection_id: connection_id,
                pk: *pk
            })
        )
    }
    fn send_connect_notification(&self, connection_id: u8) -> IoFuture<()> {
        self.send_ignore_error(
            Packet::ConnectNotification(ConnectNotification {
                connection_id: connection_id
            })
        )
    }
    fn send_disconnect_notification(&self, connection_id: u8) -> IoFuture<()> {
        self.send_ignore_error(
            Packet::DisconnectNotification(DisconnectNotification {
                connection_id: connection_id
            })
        )
    }
    fn send_pong_response(&self, ping_id: u64) -> IoFuture<()> {
        self.send(
            Packet::PongResponse(PongResponse {
                ping_id: ping_id
            })
        )
    }
    fn send_oob(&self, sender_pk: &PublicKey, data: Vec<u8>) -> IoFuture<()> {
        self.send_ignore_error(
            Packet::OobReceive(OobReceive {
                sender_pk: *sender_pk,
                data: data
            })
        )
    }
    fn send_data(&self, connection_id: u8, data: Vec<u8>) -> IoFuture<()> {
        self.send(
            Packet::Data(Data {
                connection_id: connection_id,
                data: data
            })
        )
    }
}

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
    fn insert(&self, client: Client) {
        self.connected_clients.borrow_mut()
            .insert(client.pk, client);
    }
    fn remove(&self, pk: &PublicKey) -> Option<Client> {
        self.connected_clients.borrow_mut()
            .remove(pk)
    }
    fn process_packet(&self, pk: &PublicKey, packet: Packet) -> IoFuture<()> {
        match packet {
            Packet::RouteRequest(request) => {
                let index = {
                    // check if client was already linked to pk
                    let mut clients = self.connected_clients.borrow_mut();
                    if let Some(client) = clients.get_mut(pk) {
                        if pk == &request.peer_pk {
                            // send RouteResponse(0) if client requests its own pk
                            return client.send_route_response(pk, 0)
                        }
                        let index = client.get_connection_id(&request.peer_pk);
                        if let Some(index) = index {
                            // send RouteResponse(index + 16) if client was already linked to pk
                            return client.send_route_response(&request.peer_pk, index + 16)
                        } else {
                            // try to insert new link into client.links
                            let index = client.insert_connection_id(&request.peer_pk);
                            if let Some(index) = index {
                                index
                            } else {
                                // send RouteResponse(0) if no space to insert new link
                                return client.send_route_response(&request.peer_pk, 0)
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
                let client = clients.get(&request.peer_pk).unwrap(); // can not fail
                if let Some(other_client) = clients.get(&request.peer_pk) {
                    // check if current pk is linked inside other_client
                    let other_index = other_client.get_connection_id(pk);
                    if let Some(other_index) = other_index {
                        // the are both linked, send RouteResponse and
                        // send each other ConnectNotification
                        // we don't care if connect notifications fail
                        let current_notification = client.send_connect_notification(index + 16);
                        let other_notification = other_client.send_connect_notification(other_index + 16);
                        return Box::new(
                            client.send_route_response(&request.peer_pk, index + 16)
                                .join(current_notification)
                                .join(other_notification)
                                .map(|_| ())
                        )
                    } else {
                        // if not, send RouteResponse(index + 16) only to current client
                        return Box::new(
                            client.send_route_response(&request.peer_pk, index + 16)
                        )
                    }
                } else {
                    // Do nothing because
                    // other_client has not sent RouteRequest yet to connect to this client
                    Box::new( future::ok(()) )
                }
            },
            Packet::RouteResponse(_) => {
                Box::new( future::err(
                    std::io::Error::new(std::io::ErrorKind::Other,
                        "Client must not send RouteResponse to server"
                )))
            },
            Packet::ConnectNotification(_) => {
                // ignore it for backward compatibility
                Box::new( future::ok(()) )
            },
            Packet::DisconnectNotification(notification) => {
                if notification.connection_id < 16 {
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
                        let link = client.links[notification.connection_id as usize - 16].take();
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
                        other_client.links[connection_id as usize].take();
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
            },
            Packet::PingRequest(request) => {
                if request.ping_id == 0 {
                    return Box::new( future::err(
                        std::io::Error::new(std::io::ErrorKind::Other,
                            "PingRequest.ping_id == 0"
                    )))
                }
                let clients = self.connected_clients.borrow();
                if let Some(client) = clients.get(pk) {
                    client.send_pong_response(request.ping_id)
                } else {
                    return Box::new( future::err(
                        std::io::Error::new(std::io::ErrorKind::Other,
                            "PingRequest: no such PK"
                    )) )
                }
            },
            Packet::PongResponse(response) => {
                if response.ping_id == 0 {
                    return Box::new( future::err(
                        std::io::Error::new(std::io::ErrorKind::Other,
                            "PongResponse.ping_id == 0"
                    )))
                }
                let clients = self.connected_clients.borrow();
                if let Some(client) = clients.get(pk) {
                    if response.ping_id == client.ping_id {
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
            },
            Packet::OobSend(oob) => {
                if oob.data.len() == 0 || oob.data.len() > 1024 {
                    return Box::new( future::err(
                        std::io::Error::new(std::io::ErrorKind::Other,
                            "OobSend wrong data length"
                    )))
                }
                let clients = self.connected_clients.borrow();
                if let Some(other_client) = clients.get(&oob.destination_pk) {
                    other_client.send_oob(pk, oob.data)
                } else {
                    // Do nothing because there is no other_client connected to server
                    Box::new( future::ok(()) )
                }
            },
            Packet::OobReceive(_) => {
                Box::new( future::err(
                    std::io::Error::new(std::io::ErrorKind::Other,
                        "Client must not send OobReceive to server"
                )))
            },
            Packet::Data(data) => {
                if data.connection_id < 16 {
                    return Box::new( future::err(
                        std::io::Error::new(std::io::ErrorKind::Other,
                            "Data.connection_id < 16"
                    )))
                }
                let clients = self.connected_clients.borrow();
                let other_pk = {
                    if let Some(client) = clients.get(pk) {
                        if let Some(other_pk) = client.links[data.connection_id as usize - 16] {
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
                        other_client.send_data(connection_id, data.data)
                    } else {
                        // Do nothing because
                        // other_client has not sent RouteRequest yet to connect to this client
                        Box::new( future::ok(()) )
                    }
                } else {
                    // Do nothing because there is no other_client connected to server
                    Box::new( future::ok(()) )
                }
            },
            /*
            _ => {
                Box::new( future::ok(()) )
            }
            */
        }
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
                let reader = from_client.for_each(move |packet| {
                    server_inner_c.process_packet(&client_pk, packet)
                });

                // writer = for each Packet from rx send it to client
                let writer = rx
                    .map_err(|()| unreachable!("rx can't fail"))
                    .fold(to_client, |to_client, packet| {
                        to_client.send(packet)
                    })
                    // drop to_client when rx stream is exhausted
                    .map(|_to_client| ());

                // TODO ping request = each 30s send PingRequest to client

                reader.select(writer).map(|_| ()).map_err(|(err, _)| err)
            });
        handle.spawn(process_connection.then(|_x| {
            // TODO shutdown client, send notifications etc
            println!("end of processing {:?}", _x);

            future::ok(())
        }));

        Ok(())
    });
    core.run(server).unwrap();
}
