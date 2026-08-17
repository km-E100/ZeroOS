#![no_std]

use heapless::Vec;
use log::{info, warn};
use spin::Mutex;
use userlib;
use zero_abi::channels;
use zero_abi::ipc::Message;

#[derive(Clone)]
struct Channel {
    id: u32,
    subscribers: Vec<u32, 8>,
}

static CHANNELS: Mutex<[Channel; 4]> = Mutex::new([
    Channel::new(1),
    Channel::new(2),
    Channel::new(3),
    Channel::new(4),
]);

const CMD_SUBSCRIBE: u32 = 0xFFFF_0001;
const CMD_UNSUBSCRIBE: u32 = 0xFFFF_0002;

pub extern "C" fn server_main() -> ! {
    info!("IPC router online");
    loop {
        let mut message = Message::empty();
        match userlib::ipc_receive(channels::IPC_ROUTER_BUS, &mut message) {
            Ok(_) => dispatch_message(&mut message),
            Err(_) => userlib::yield_now(),
        }
    }
}

fn dispatch_message(msg: &mut Message) {
    if process_control(msg) {
        return;
    }
    if let Some(channel) = find_channel(msg.code) {
        info!("routing message on channel {}", channel.id);
        notify_subscribers(channel, msg);
    } else {
        warn!("unknown channel {}", msg.code);
    }
}

fn process_control(msg: &Message) -> bool {
    match msg.code {
        CMD_SUBSCRIBE => {
            if let Some((channel, subscriber)) = decode_pair(&msg.payload) {
                subscribe(channel, subscriber);
            }
            true
        }
        CMD_UNSUBSCRIBE => {
            if let Some((channel, subscriber)) = decode_pair(&msg.payload) {
                unsubscribe(channel, subscriber);
            }
            true
        }
        _ => false,
    }
}

fn find_channel(id: u32) -> Option<Channel> {
    let pool = CHANNELS.lock();
    pool.iter().find(|ch| ch.id == id).cloned()
}

fn notify_subscribers(channel: Channel, _msg: &Message) {
    for subscriber in channel.subscribers.iter() {
        if let Err(err) = userlib::ipc_send(*subscriber, _msg) {
            warn!(
                "ipc: failed to deliver channel {} message to {}: {:?}",
                channel.id, subscriber, err
            );
        }
    }
}

impl Channel {
    const fn new(id: u32) -> Self {
        Self {
            id,
            subscribers: Vec::new(),
        }
    }
}

fn decode_pair(payload: &[u8]) -> Option<(u32, u32)> {
    if payload.len() < 8 {
        return None;
    }
    let first = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let second = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    Some((first, second))
}

fn subscribe(channel_id: u32, subscriber: u32) {
    let mut table = CHANNELS.lock();
    if let Some(channel) = table.iter_mut().find(|ch| ch.id == channel_id) {
        if !channel.subscribers.contains(&subscriber) {
            let _ = channel.subscribers.push(subscriber);
        }
    }
}

fn unsubscribe(channel_id: u32, subscriber: u32) {
    let mut table = CHANNELS.lock();
    if let Some(channel) = table.iter_mut().find(|ch| ch.id == channel_id) {
        if let Some(pos) = channel.subscribers.iter().position(|id| *id == subscriber) {
            channel.subscribers.remove(pos);
        }
    }
}
