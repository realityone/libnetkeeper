use std::net::Ipv4Addr;
use std::{result, str};

use byteorder::{ByteOrder, NetworkEndian};

use common::bytes::{BytesAble, BytesAbleNum};
use common::hex::ToHex;
use common::utils::current_timestamp;
use crypto::hash::{HasherBuilder, HasherType};

#[derive(Debug)]
pub enum ParseAttributesError {
    // Expect length {}, got {}
    UnexpectDataLength(usize, usize),
}

type AttributeResult<T> = result::Result<T, ParseAttributesError>;

#[derive(Debug, Copy, Clone)]
pub enum AttributeValueType {
    TInteger = 0x0,
    TIPAddress = 0x1,
    // or Integer array?
    TString = 0x2,
    TGroup = 0x3,
    // Attributes group
}

#[derive(Debug, Copy, Clone)]
pub enum AttributeType {
    TAttribute,
    TUserName,
    TClientIPAddress,
    TClientVersion,
    TClientType,
    TOSVersion,
    TOSLang,
    TAdapterInfo,
    TCPUInfo,
    TMACAddress,
    TMemorySize,
    TDefaultExplorer,
    TBubble,
    TBubbleId,
    TBubbleTitle,
    TBubbleContext,
    TBubbleContextURL,
    TBubbleKeepTime,
    TBubbleDelayTime,
    TBubbleType,
    TChannel,
    TChannelNote,
    TChannelContextURL,
    TChannelContextURL2,
    TChannelOrder,
    TPlugin,
    TPluginName,
    TPluginConfigureData,
    TUpdateVersion,
    TUpdateDownloadURL,
    TUpdateDescription,
    TKeepAliveTime,
    TKeepAliveInterval,
    TKeepAliveData,
    TProcessCheckInterval,
    TProcessCheckList,
    TRealTimeBubbleServer,
    TRealTimeBubbleInterval,
    TWifiTransmitIPList,
    TWifiShareNumber,
    TWifiShareCode,
    TWifiShareErrorString,
    TWifiShareBindRequired,
    TPlugin2,
    TDeviceSN,
    TDeviceType,
    TWifiRedirectURL,
}

#[derive(Debug)]
pub struct Attribute {
    name:          String,
    parent_id:     u8,
    attribute_id:  u8,
    value_type_id: u8,
    data:          Vec<u8>,
}

pub struct KeepaliveDataCalculator;

pub trait AttributeValue: BytesAble {}

pub trait AttributeVec {
    fn as_bytes(&self) -> Vec<u8>;
    fn length(&self) -> u16;

    fn from_bytes(bytes: &[u8]) -> AttributeResult<Vec<Attribute>>;
}

impl Attribute {
    pub fn new(
        name: &str,
        parent_id: u8,
        attribute_id: u8,
        value_type_id: u8,
        data: Vec<u8>,
    ) -> Self {
        Attribute {
            name: name.to_string(),
            parent_id,
            attribute_id,
            value_type_id,
            data,
        }
    }

    pub fn from_type<V>(attribute_type: AttributeType, value: &V) -> Self
    where
        V: AttributeValue,
    {
        Self::new(
            attribute_type.name(),
            attribute_type.parent().id(),
            attribute_type.id(),
            attribute_type.value_type() as u8,
            value.as_bytes().to_vec(),
        )
    }

    fn header_length() -> u16 {
        3u16
    }

    pub fn length(&self) -> u16 {
        self.data_length() + Self::header_length()
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut attribute_bytes = Vec::new();
        {
            let raw_attribute_id = self.attribute_id as u8;
            attribute_bytes.push(raw_attribute_id);
            attribute_bytes.extend(self.length().as_bytes_be());
            attribute_bytes.extend_from_slice(&self.data);
        }
        attribute_bytes
    }

    fn data_length(&self) -> u16 {
        self.data.len() as u16
    }
}

impl KeepaliveDataCalculator {
    pub fn calculate(timestamp: Option<u32>, last_data: Option<&str>) -> String {
        let timenow = timestamp.unwrap_or_else(current_timestamp);
        let salt = last_data.unwrap_or("llwl");

        let keepalive_data;
        {
            let mut md5 = HasherBuilder::build(HasherType::MD5);
            md5.update(&timenow.as_bytes_be());
            md5.update(salt.as_bytes());

            let hashed_bytes = md5.finish();
            keepalive_data = hashed_bytes[..].to_hex();
        }
        keepalive_data
    }
}

impl AttributeType {
    pub fn name(self) -> &'static str {
        match self {
            AttributeType::TUserName => "User-Name",
            AttributeType::TClientIPAddress => "Client-IP-Address",
            AttributeType::TClientVersion => "Client-Version",
            AttributeType::TClientType => "Client-Type",
            AttributeType::TOSVersion => "OS-Version",
            AttributeType::TOSLang => "OS-Lang",
            AttributeType::TAdapterInfo => "Adapter-Info",
            AttributeType::TCPUInfo => "CPU-Info",
            AttributeType::TMACAddress => "MAC-Address",
            AttributeType::TMemorySize => "Memory-Size",
            AttributeType::TDefaultExplorer => "Default-Explorer",
            AttributeType::TBubble => "Bubble",
            AttributeType::TBubbleId => "Bubble-Id",
            AttributeType::TBubbleTitle => "Bubble-Title",
            AttributeType::TBubbleContext => "Bubble-Context",
            AttributeType::TBubbleContextURL => "Bubble-Context-URL",
            AttributeType::TBubbleKeepTime => "Bubble-Keep-Time",
            AttributeType::TBubbleDelayTime => "Bubble-Delay-Time",
            AttributeType::TBubbleType => "Bubble-Type",
            AttributeType::TChannel => "Channel",
            AttributeType::TChannelNote => "Channel-Note",
            AttributeType::TChannelContextURL => "Channel-Context-URL",
            AttributeType::TChannelContextURL2 => "Channel-Context-URL",
            AttributeType::TChannelOrder => "Channel-Order",
            AttributeType::TPlugin => "Plugin",
            AttributeType::TPluginName => "Plugin-Name",
            AttributeType::TPluginConfigureData => "Plugin-Configure-Data",
            AttributeType::TUpdateVersion => "Update-Version",
            AttributeType::TUpdateDownloadURL => "Update-Download-URL",
            AttributeType::TUpdateDescription => "Update-Description",
            AttributeType::TKeepAliveTime => "KeepAlive-Time",
            AttributeType::TKeepAliveInterval => "KeepAlive-Interval",
            AttributeType::TKeepAliveData => "KeepAlive-Data",
            AttributeType::TProcessCheckInterval => "Process-Check-Interval",
            AttributeType::TProcessCheckList => "Process-Check-List",
            AttributeType::TRealTimeBubbleServer => "RealTime-Bubble-Server",
            AttributeType::TRealTimeBubbleInterval => "RealTime-Bubble-Interval",
            AttributeType::TWifiTransmitIPList => "Wifi-Transmit-IP-List",
            AttributeType::TWifiShareNumber => "Wifi-Share-Number",
            AttributeType::TWifiShareCode => "Wifi-Share-Code",
            AttributeType::TWifiShareErrorString => "Wifi-Share-Error-String",
            AttributeType::TWifiShareBindRequired => "Wifi-Share-Bind-Required",
            AttributeType::TPlugin2 => "Plugin",
            AttributeType::TDeviceSN => "Device-SN",
            AttributeType::TDeviceType => "Device-Type",
            AttributeType::TWifiRedirectURL => "Wifi-Redirect-URL",

            _ => "",
        }
    }

    pub fn id(self) -> u8 {
        match self {
            AttributeType::TAttribute => 0x0,
            AttributeType::TUserName => 0x1,
            AttributeType::TClientIPAddress => 0x2,
            AttributeType::TClientVersion => 0x3,
            AttributeType::TClientType => 0x4,
            AttributeType::TOSVersion => 0x5,
            AttributeType::TOSLang => 0x6,
            AttributeType::TAdapterInfo => 0x7,
            AttributeType::TCPUInfo => 0x8,
            AttributeType::TMACAddress => 0x9,
            AttributeType::TMemorySize => 0xa,
            AttributeType::TDefaultExplorer => 0xb,
            AttributeType::TBubble => 0xc,
            AttributeType::TBubbleId => 0x1,
            AttributeType::TBubbleTitle => 0x2,
            AttributeType::TBubbleContext => 0x3,
            AttributeType::TBubbleContextURL => 0x4,
            AttributeType::TBubbleKeepTime => 0x5,
            AttributeType::TBubbleDelayTime => 0x6,
            AttributeType::TBubbleType => 0x7,
            AttributeType::TChannel => 0xd,
            AttributeType::TChannelNote => 0x1,
            AttributeType::TChannelContextURL => 0x2,
            AttributeType::TChannelContextURL2 => 0x3,
            AttributeType::TChannelOrder => 0x4,
            AttributeType::TPlugin => 0xe,
            AttributeType::TPluginName => 0x1,
            AttributeType::TPluginConfigureData => 0x2,
            AttributeType::TUpdateVersion => 0xf,
            AttributeType::TUpdateDownloadURL => 0x10,
            AttributeType::TUpdateDescription => 0x11,
            AttributeType::TKeepAliveTime => 0x12,
            AttributeType::TKeepAliveInterval => 0x13,
            AttributeType::TKeepAliveData => 0x14,
            AttributeType::TProcessCheckInterval => 0x15,
            AttributeType::TProcessCheckList => 0x16,
            AttributeType::TRealTimeBubbleServer => 0x17,
            AttributeType::TRealTimeBubbleInterval => 0x18,
            AttributeType::TWifiTransmitIPList => 0x19,
            AttributeType::TWifiShareNumber => 0x1a,
            AttributeType::TWifiShareCode => 0x1b,
            AttributeType::TWifiShareErrorString => 0x1c,
            AttributeType::TWifiShareBindRequired => 0x1d,
            AttributeType::TPlugin2 => 0x1e,
            AttributeType::TDeviceSN => 0x1,
            AttributeType::TDeviceType => 0x2,
            AttributeType::TWifiRedirectURL => 0x1f,
        }
    }

    pub fn parent(self) -> Self {
        match self {
            AttributeType::TBubbleId
            | AttributeType::TBubbleTitle
            | AttributeType::TBubbleContext
            | AttributeType::TBubbleContextURL
            | AttributeType::TBubbleKeepTime
            | AttributeType::TBubbleDelayTime
            | AttributeType::TBubbleType => AttributeType::TBubble,

            AttributeType::TChannelNote
            | AttributeType::TChannelContextURL
            | AttributeType::TChannelContextURL2
            | AttributeType::TChannelOrder => AttributeType::TChannel,

            AttributeType::TPluginName | AttributeType::TPluginConfigureData => {
                AttributeType::TPlugin
            }

            AttributeType::TDeviceSN | AttributeType::TDeviceType => AttributeType::TPlugin2,

            _ => AttributeType::TAttribute,
        }
    }

    pub fn value_type(self) -> AttributeValueType {
        match self {
            AttributeType::TClientIPAddress => AttributeValueType::TIPAddress,

            AttributeType::TBubble
            | AttributeType::TChannel
            | AttributeType::TPlugin
            | AttributeType::TPlugin2 => AttributeValueType::TGroup,

            AttributeType::TMemorySize
            | AttributeType::TBubbleId
            | AttributeType::TBubbleKeepTime
            | AttributeType::TBubbleDelayTime
            | AttributeType::TBubbleType
            | AttributeType::TChannelOrder
            | AttributeType::TKeepAliveTime
            | AttributeType::TKeepAliveInterval
            | AttributeType::TProcessCheckInterval
            | AttributeType::TRealTimeBubbleInterval
            | AttributeType::TWifiShareNumber
            | AttributeType::TWifiShareCode
            | AttributeType::TWifiShareBindRequired => AttributeValueType::TInteger,

            _ => AttributeValueType::TString,
        }
    }
}

impl AttributeVec for Vec<Attribute> {
    fn as_bytes(&self) -> Vec<u8> {
        let mut attributes_bytes: Vec<u8> = Vec::new();
        for attr in self {
            attributes_bytes.extend(attr.as_bytes());
        }
        attributes_bytes
    }

    fn length(&self) -> u16 {
        self.iter().fold(0, |sum, attr| sum + attr.length()) as u16
    }

    /// Now only support parse from `AttributeType::TAttribute`'s attributes,
    /// `parent_id` and `value_type_id` will be missed.
    fn from_bytes(bytes: &[u8]) -> AttributeResult<Vec<Attribute>> {
        let mut index = 0;
        let mut attributes: Vec<Attribute> = Vec::new();
        let header_length = Attribute::header_length() as usize;
        loop {
            let cursor = &bytes[index..];
            let bytes_length = cursor.len() as usize;
            if bytes_length == 0 {
                return Ok(attributes);
            }
            if bytes_length < header_length {
                return Err(ParseAttributesError::UnexpectDataLength(
                    header_length,
                    bytes_length,
                ));
            }
            let attribute_id = cursor[0];

            let data_length = NetworkEndian::read_u16(&cursor[1..header_length]) as usize;
            index += data_length;

            if data_length > bytes_length {
                return Err(ParseAttributesError::UnexpectDataLength(
                    data_length,
                    bytes_length,
                ));
            }

            let mut data: Vec<u8> = Vec::new();
            data.extend_from_slice(&cursor[header_length..data_length]);
            attributes.push(Attribute::new("", 0u8, attribute_id, 0u8, data))
        }
    }
}

impl AttributeValue for String {}

impl AttributeValue for Ipv4Addr {}

impl AttributeValue for u32 {}

#[test]
fn test_attribute_gen_bytes() {
    let un = Attribute::from_type(AttributeType::TUserName, &"05802278989@HYXY.XY".to_string());
    let assert_data: &[u8] = &[
        1, 0, 22, 48, 53, 56, 48, 50, 50, 55, 56, 57, 56, 57, 64, 72, 89, 88, 89, 46, 88, 89,
    ];
    assert_eq!(&un.as_bytes()[..], assert_data);
}

#[test]
fn test_attributes_parse_bytes() {
    let assert_data: &[u8] = &[
        2, 0, 7, 10, 0, 0, 1, 3, 0, 12, 49, 46, 50, 46, 50, 50, 46, 51, 54, 20, 0, 35, 102, 102,
        98, 48, 98, 50, 97, 102, 57, 52, 54, 57, 51, 102, 100, 49, 98, 97, 52, 99, 57, 51, 101, 54,
        98, 57, 97, 101, 98, 100, 51, 102, 18, 0, 7, 87, 196, 78, 204, 1, 0, 22, 48, 53, 56, 48,
        50, 50, 55, 56, 57, 56, 57, 64, 72, 89, 88, 89, 46, 88, 89,
    ];
    let attributes: Vec<Attribute> = Vec::<Attribute>::from_bytes(assert_data).unwrap();
    assert_eq!(attributes.as_bytes(), assert_data);
}

#[test]
fn test_keepalive_data() {
    let kp_data1 = KeepaliveDataCalculator::calculate(Some(1472483020), None);
    let kp_data2 = KeepaliveDataCalculator::calculate(
        Some(1472483020),
        Some("ffb0b2af94693fd1ba4c93e6b9aebd3f"),
    );
    assert_eq!(kp_data1, "ffb0b2af94693fd1ba4c93e6b9aebd3f");
    assert_eq!(kp_data2, "d0dce2b013c8adfac646a2917fdab802");
}

// [[SNAttributeType alloc] initWithHuman:@"User-Name" :0x0 :0x1 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Client-IP-Address" :0x0 :0x2 :0x1];
// [[SNAttributeType alloc] initWithHuman:@"Client-Version" :0x0 :0x3 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Client-Type" :0x0 :0x4 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"OS-Version" :0x0 :0x5 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"OS-Lang" :0x0 :0x6 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Adapter-Info" :0x0 :0x7 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"CPU-Info" :0x0 :0x8 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"MAC-Address" :0x0 :0x9 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Memory-Size" :0x0 :0xa :0x0];
// [[SNAttributeType alloc] initWithHuman:@"Default-Explorer" :0x0 :0xb :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Bubble" :0x0 :0xc :0x3];
// [[SNAttributeType alloc] initWithHuman:@"Bubble-Id" :0xc :0x1 :0x0];
// [[SNAttributeType alloc] initWithHuman:@"Bubble-Title" :0xc :0x2 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Bubble-Context" :0xc :0x3 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Bubble-Context-URL" :0xc :0x4 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Bubble-Keep-Time" :0xc :0x5 :0x0];
// [[SNAttributeType alloc] initWithHuman:@"Bubble-Delay-Time" :0xc :0x6 :0x0];
// [[SNAttributeType alloc] initWithHuman:@"Bubble-Type" :0xc :0x7 :0x0];
// [[SNAttributeType alloc] initWithHuman:@"Channel" :0x0 :0xd :0x3];
// [[SNAttributeType alloc] initWithHuman:@"Channel-Note" :0xd :0x1 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Channel-Context-URL" :0xd :0x2 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Channel-Context-URL" :0xd :0x3 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Channel-Order" :0xd :0x4 :0x0];
// [[SNAttributeType alloc] initWithHuman:@"Plugin" :0x0 :0xe :0x3];
// [[SNAttributeType alloc] initWithHuman:@"Plugin-Name" :0xe :0x1 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Plugin-Configure-Data" :0xe :0x2 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Update-Version" :0x0 :0xf :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Update-Download-URL" :0x0 :0x10 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Update-Description" :0x0 :0x11 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"KeepAlive-Time" :0x0 :0x12 :0x0];
// [[SNAttributeType alloc] initWithHuman:@"KeepAlive-Interval" :0x0 :0x13 :0x0];
// [[SNAttributeType alloc] initWithHuman:@"KeepAlive-Data" :0x0 :0x14 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Process-Check-Interval" :0x0 :0x15 :0x0];
// [[SNAttributeType alloc] initWithHuman:@"Process-Check-List" :0x0 :0x16 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"RealTime-Bubble-Server" :0x0 :0x17 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"RealTime-Bubble-Interval" :0x0 :0x18 :0x0];
// [[SNAttributeType alloc] initWithHuman:@"Wifi-Transmit-IP-List" :0x0 :0x19 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Wifi-Share-Number" :0x0 :0x1a :0x0];
// [[SNAttributeType alloc] initWithHuman:@"Wifi-Share-Code" :0x0 :0x1b :0x0];
// [[SNAttributeType alloc] initWithHuman:@"Wifi-Share-Error-String" :0x0 :0x1c :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Wifi-Share-Bind-Required" :0x0 :0x1d :0x0];
// [[SNAttributeType alloc] initWithHuman:@"Plugin" :0x0 :0x1e :0x3];
// [[SNAttributeType alloc] initWithHuman:@"Device-SN" :0x1e :0x1 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Device-Type" :0x1e :0x2 :0x2];
// [[SNAttributeType alloc] initWithHuman:@"Wifi-Redirect-URL" :0x0 :0x1f :0x2];
