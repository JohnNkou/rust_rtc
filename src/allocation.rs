use crate::Response;
use crate::attribute::Attribute;
use crate::header::Header;
use std::str::FromStr;
use std::net::{ UdpSocket, SocketAddr };
use std::collections::{HashMap};
use std::thread::{spawn, JoinHandle};
use std::sync::{Arc,Mutex};


pub struct Allocation {
	pub thread: JoinHandle<()>,
	pub peers: Arc<Mutex<HashMap<String, SocketAddr>>>,
	pub socket: Arc<UdpSocket>,
	pub origin : Arc<SocketAddr>
}

#[allow(non_snake_case)]
impl Allocation {
	pub fn new(port: u16, origin: SocketAddr,Attributes: Arc<HashMap<[u8;2],(String,String)>>) -> Allocation{
		let peers = Arc::new(Mutex::new(HashMap::new()));
		let ip_string = "127.0.0.1".to_string() + ":" + &(port.to_string());
		let addr = SocketAddr::from_str(&ip_string).unwrap();
		let socket = Arc::new(UdpSocket::bind(addr).unwrap());
		let or = Arc::new(origin);

		let cloned = socket.clone();

		let thread = Allocation::start_allocation_thread(peers.clone(),cloned,or.clone(), Attributes);

		return Allocation { thread, peers, socket, origin:or }
	}

	pub fn start_allocation_thread(_peers: Arc<Mutex<HashMap<String,SocketAddr>>>, socket: Arc<UdpSocket>, transport: Arc<SocketAddr>, Attributes : Arc<HashMap<[u8;2],(String,String)>>) -> JoinHandle<()>{
		spawn(move || {
			let mut buf = [0;1024];

			loop {
				match socket.recv_from(&mut buf).unwrap(){
					(size,origin) =>{
						let data = &buf[0..size];
						let header = Header::from(Header::DATA,0,[15;12],origin).unwrap();
						let mut response = Response::new(&header);

						response.setIndication().add_xor_attribute(&Attribute::XOR_PEER_ADDRESS,&origin,&Attributes).add_data_attribute(data,Attributes.clone()).build();

						let buf_response = response.getData();

						socket.send_to(&buf_response, *transport).unwrap();

						println!("DATA SENT FROM {:?} TO {:?}", origin,transport);
						
						response.getResumer();
					},
					_ =>{
						break;
					}
				}
			}
		})
	}

	pub fn add_peer(&mut self, addr: SocketAddr){
		let st = addr.to_string();
		let mut peers = self.peers.lock().unwrap();

		peers.insert(st,addr);
	}
}