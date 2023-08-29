use iced::executor::Default;
use iced::widget::button::Appearance;
use iced::{Settings, Theme, Length, clipboard, Application, Font, font};
use iced::widget::{Text, Button, button, Column, Row, Container, toggler, TextInput, Scrollable};
use iced::widget::qr_code::{self, QRCode};
use iced::alignment::Vertical::Top;
use iced::alignment::Horizontal::Right;
use iced_aw::style::colors::{LIGHT, BLACK};
use iced_aw::{Card, Modal, style::CardStyles};

use std::process::{Command, Output};
use std::error::Error;
use bluer::{Adapter, Address, AdapterEvent, DeviceEvent, Device};
use futures::executor::block_on;
use tokio::runtime::Runtime;
use std::{collections::HashSet, env};
use futures::{pin_mut, stream::SelectAll, StreamExt};
use tokio::time::{Duration, sleep};
use std::borrow::Cow;

fn main() -> Result<(), iced::Error> {
    Runtime::new().expect("Failed to create Tokio runtime");
    WifiStatus::run(Settings::default()) /*{ 
        id: Some(String::from("migue07juegos_controlcenter")), 
        window: (iced::window::Settings::default()), 
        flags: (), 
        default_font: (Font::with_name("FontAwesome6Pro-Light")), 
        default_text_size: (16.0), 
        antialiasing: (true), 
        exit_on_close_request: (true) 
    })*/
}

const ICON_FONT: &[u8] = include_bytes!("../fonts/font-awesome-6-light.otf");

struct GreenButton {}
impl button::StyleSheet for GreenButton {
    type Style = Theme;

    fn active(&self, _: &Self::Style) -> button::Appearance {
        button::Appearance {
            background: Some(iced::Color::from_rgb(0.0, 0.73, 0.0).into()),
            ..Appearance::default()
        }
    }
}

struct OrangeButton {}
impl button::StyleSheet for OrangeButton {
    type Style = Theme;

    fn active(&self, _: &Self::Style) -> button::Appearance {
        button::Appearance {
            background: Some(iced::Color::from_rgb(0.94, 0.43, 0.0).into()),
            ..Appearance::default()
        }
    }
}

struct WifiStatus {
    status: bool,
    scan: bool,
    password: bool,
    password_str: String,
    ssid: String,
    section: bool,
    settings: bool,
    show_password: bool,
    security: String,
    qr_code: Option<qr_code::State>,

    bluetooth_status: bool,
    bluetooth_adapter: Adapter,
    scan_bluetooth: bool,
    bluetooth_devices: Vec<BluetoothDeviceInfo>,
    bluetooth_settings: bool,
    bluetooth_device_addr: [u8; 6],
}

#[derive(Debug, Clone)]
enum WifiMessage {
    Connect(String,String),
    Disconnect(String),
    ToggleWifi(bool),
    Scan(bool),
    PasswordPopup(bool,String),
    InputChanged(String),
    Quit,
    Section(bool),
    ConnectKnown(String),
    OpenSettings(bool,String),
    Forget(String),
    ShowPassword(bool),
    Copy(String),

    ToggleBluetooth(bool),
    ScanBluetooth(bool),
    PairBluetooth(Device),
    ConnectBluetooth(Device),
    DisconnectBluetooth(Device),
    SettingsBluetooth(bool,[u8; 6]),
    RemoveBluetooth,
}

impl Application for WifiStatus {
    type Executor = iced::executor::Default;
    type Message = WifiMessage;
    type Theme = Theme;
    type Flags = ();
    fn theme(&self) -> Theme {
        Theme::Dark
    }

    fn new(_flags: ()) -> (Self, iced::Command<Self::Message>) {
        let adapter = block_on(bluetooth_adapter()).unwrap();
        let bluetooth_devices = Vec::new();
        font::load(ICON_FONT);
        (
        WifiStatus { 
            status: is_wifi_enabled(),
            scan: false,
            password: false,
            password_str: "".to_string(),
            ssid: "".to_string(),
            section: false,
            settings: false,
            show_password: false,
            security: "".to_string(),
            qr_code: None,
            bluetooth_status: block_on(is_bluetooth_enabled(&adapter)),
            bluetooth_adapter: adapter,
            scan_bluetooth: false,
            bluetooth_devices,
            bluetooth_settings: false,
            bluetooth_device_addr: [0,0,0,0,0,0],
        },
        iced::Command::none()
        )
    }

    fn title(&self) -> String {
        String::from("Wifi test")
    }

    fn update(&mut self, message: Self::Message) -> iced::Command<Self::Message> {
        match message {
            WifiMessage::Connect(value,value2) => {connect_to_network(&value, &value2); self.password = false },
            WifiMessage::Disconnect(value) => disconnect_network(&value),

            WifiMessage::ToggleWifi(value) => { if value {
                let _ = Command::new("nmcli").args(&["radio", "wifi", "on"]).output();
            } else {
                let _ = Command::new("nmcli").args(&["radio", "wifi", "off"]).output();
            } 
            self.status = value
            },

            WifiMessage::Scan(value) => self.scan = value,
            WifiMessage::PasswordPopup(value,value2) => {self.password = value; self.ssid = value2; self.password_str = "".to_string();},
            WifiMessage::InputChanged(value) => self.password_str = value,
            WifiMessage::Quit => std::process::exit(0),
            WifiMessage::Section(value) => self.section = value,
            WifiMessage::ConnectKnown(value) => connect_to_known_network(&value),
            WifiMessage::OpenSettings(value,value2) => { self.settings = value; self.ssid = value2},
            WifiMessage::Forget(value) => { _ = Command::new("nmcli").args(&["connection", "delete", &value]).output(); self.settings = false },
            WifiMessage::Copy(value) => { return clipboard::write(String::from(value)) }

            WifiMessage::ShowPassword(value) => {
                self.show_password = value;
                if self.show_password {
                    (self.ssid,self.security,self.password_str) = show_password()
                };
                self.qr_code = qr_code::State::new((format!("WIFI:S:{};T:{};P:{};;", self.ssid, self.security, self.password_str)).to_string()).ok()
            },

            WifiMessage::ToggleBluetooth(value) => { block_on(able_bluetooth(&self.bluetooth_adapter, value));
            self.bluetooth_status = value
            },
            WifiMessage::ScanBluetooth(value) => {
                self.scan_bluetooth = value;
                if value {
                    match block_on(discover_bluetooth_devices(&self.bluetooth_adapter)) {
                        Ok(devices) => self.bluetooth_devices = devices,
                        Err(err) => eprintln!("Error scanning Bluetooth devices: {:?}", err),
                    }
                }
            }
            WifiMessage::PairBluetooth(value) => { block_on(pair_device(value.clone())); let _ = block_on(connect_device(value));},
            WifiMessage::ConnectBluetooth(value) => { let _ = block_on(connect_device(value)); },
            WifiMessage::DisconnectBluetooth(value) => block_on(disconnect_device(value)),
            WifiMessage::SettingsBluetooth(value, value2) => { self.bluetooth_settings = value; self.bluetooth_device_addr = value2},
            WifiMessage::RemoveBluetooth => block_on(remove_device(&self.bluetooth_adapter, self.bluetooth_device_addr)),
        }
        iced::Command::none()
    }

    fn view(&self) -> iced::Element<'_,Self::Message> {
        let mut wifi_vec: Vec<iced::Element<'_, WifiMessage>> = Vec::new();

        if self.scan {
            for pair in get_networks() {
                if pair.in_use == "*" {
                    let button = Row::new()
                        .push(Button::new(Text::new(pair.ssid.clone()))
                            .on_press(WifiMessage::Disconnect(pair.ssid.clone()))
                            .style(iced::theme::Button::Custom(Box::new(GreenButton {})))
                        )
                        .push(Button::new(Text::new('\u{f013}'.to_string()).font(Font::with_name("Font Awesome 6 Pro Light")))
                            .on_press(WifiMessage::OpenSettings(true,pair.ssid.clone()))
                        )
                        .push(Button::new(Text::new('\u{f084}'.to_string()).font(Font::with_name("Font Awesome 6 Pro Light")))
                            .on_press(WifiMessage::ShowPassword(true))
                        )
                        .spacing(10).into();
                        wifi_vec.push(button);
                } else if String::from_utf8_lossy(&Command::new("nmcli")
                    .args(&["-f", "NAME", "connection", "show"])
                    .output().unwrap()
                    .stdout
                )
                .split('\n')
                .any(|line| line.trim() == pair.ssid) {
                    let button = Row::new()
                    .push(Button::new(Text::new(pair.ssid.clone()))
                        .style(iced::theme::Button::Custom(Box::new(OrangeButton {})))
                        .on_press(WifiMessage::ConnectKnown(pair.ssid.clone())))
                    .push(Button::new(Text::new('\u{f013}'.to_string()).font(Font::with_name("Font Awesome 6 Pro Light")))
                        .on_press(WifiMessage::OpenSettings(true,pair.ssid.clone()))
                    )
                    .spacing(10).into();
                    wifi_vec.push(button);
                } else {
                    let button = Row::new()
                    .push(Button::new(Text::new(pair.ssid.clone()))
                        .on_press(WifiMessage::PasswordPopup(true, pair.ssid.clone())))
                    .spacing(10).into();
                    wifi_vec.push(button);
                }
            }
        }

        let mut bluetooth_vec: Vec<iced::Element<'_, WifiMessage>> = Vec::new();

        if self.scan_bluetooth {
            //print_bluetooth_devices(&self.bluetooth_devices);
            for device in &self.bluetooth_devices {
                if device.name != None {
                    if device.connected {
                            let button = Row::new()
                            .push(Button::new(Text::new(device.name.as_ref().unwrap()))
                                .on_press(WifiMessage::DisconnectBluetooth(self.bluetooth_adapter.device(device.addr).unwrap()))
                                .style(iced::theme::Button::Custom(Box::new(GreenButton {}))))
                            .spacing(10).into();
                            bluetooth_vec.push(button);
                    } else if device.paired {
                                let button = Row::new()
                                    .push(Button::new(Text::new(device.name.as_ref().unwrap()))
                                        .on_press(WifiMessage::ConnectBluetooth(self.bluetooth_adapter.device(device.addr).unwrap()))
                                        .style(iced::theme::Button::Custom(Box::new(OrangeButton {}))))
                                    .push(Button::new(Text::new('\u{f013}'.to_string()).font(Font::with_name("Font Awesome 6 Pro Light")))
                                        .on_press(WifiMessage::SettingsBluetooth(true, *device.addr))
                                    )
                                    .spacing(10).into();
                                bluetooth_vec.push(button);
                    } else {
                        let button = Row::new()
                        .push(Button::new(Text::new(device.name.as_ref().unwrap()))
                            .on_press(WifiMessage::PairBluetooth(self.bluetooth_adapter.device(device.addr).unwrap())))
                        .spacing(10).into();
                        bluetooth_vec.push(button);
                    }
                }
            }
        }

        let wifi_tog = toggler(String::from("Enable wifi"), self.status , WifiMessage::ToggleWifi);
        let scan_button = Button::new("Scan").on_press(WifiMessage::Scan(true));

        let bluetooth_tog = toggler(String::from("Enable bluetooth"), self.bluetooth_status, WifiMessage::ToggleBluetooth);
        let bluetooth_scan = Button::new("Scan").on_press(WifiMessage::ScanBluetooth(true));

        let bluetooth_button: Button<WifiMessage> = Button::new(" Bluetooth ").on_press(WifiMessage::Section(true));
        let wifi_button: Button<WifiMessage> = Button::new("        Wifi       ").on_press(WifiMessage::Section(false));
        
        let top_bar = Container::new(Button::new(Text::new('\u{f00d}'.to_string())
                //.font(Font::with_name("Font Awesome 6 Pro Light"))
                .font(Font{
                    family: font::Family::Name("Font Awesome 6 Pro Light"),
                    weight: font::Weight::Normal,
                    stretch: font::Stretch::default(),
                    monospaced: false,
                })
            )
            .on_press(WifiMessage::Quit)
        ).width(Length::Fill)
        .align_x(Right);
        
        let wifi_col = Column::new()
            .spacing(10)
            .push(wifi_tog)
            .push(scan_button)
            .push(Scrollable::new(Column::with_children(wifi_vec).spacing(10)).width(Length::Fill));

        let bluetooth_col = Column::new()
            .spacing(10)
            .push(bluetooth_tog)
            .push(bluetooth_scan)
            .push(Scrollable::new(Column::with_children(bluetooth_vec).spacing(10)).width(Length::Fill));

        let sidebar: Column<WifiMessage> = Column::new()
            .spacing(10)
            .push(wifi_button)
            .push(bluetooth_button);
        

        let all_row: Row<WifiMessage> = Row::new()
            .spacing(20)
            .push(sidebar)
            .push(if self.section {
                    bluetooth_col
                } else {
                    wifi_col
                });
        
        let all_col: Column<WifiMessage> = Column::new()
            .spacing(25)
            .push(top_bar)
            .push(all_row);

        let content: Container<WifiMessage> = Container::new(all_col)
            .center_x()
            .align_y(Top)
            .padding(20)
            .width(iced::Length::Fill)
            .height(iced::Length::Fill)
            .into();

        let password_modal: Modal<WifiMessage> = Modal::new(self.password, content, {
            let password = &self.password_str;
            Container::new(
                Column::new()
                .push(
                    Card::new(Text::new("Password"),Column::new()
                        .spacing(10)
                        .align_items(iced::Alignment::Center)
                        .push(TextInput::new("Type password:", &password)
                            .on_input(WifiMessage::InputChanged)
                            .password()
                            .on_submit(WifiMessage::Connect(self.ssid.clone(), password.to_string()))
                        )
                        .push(Row::new()
                            .push(Column::new()
                                .push(Button::new("Cancel")
                                    .on_press(WifiMessage::PasswordPopup(false,"".to_string()))
                                )
                                .align_items(iced::Alignment::Center)
                                .width(Length::Fill))
                            .push(Column::new()
                                .push(Button::new("Submit")
                                    .on_press(WifiMessage::Connect(self.ssid.clone(), password.to_string()))
                                )
                                .align_items(iced::Alignment::Center)
                                .width(Length::Fill)
                            )
                        )
                    )
                    .style(CardStyles::Primary)
                )
            )
        .width(Length::Fixed(400.0))
        .center_x()
        .center_y()
        }
        )
        .on_esc(WifiMessage::PasswordPopup(false, "".to_string()))
        .backdrop(WifiMessage::PasswordPopup(false, "".to_string()))
        .into();

        let settings_modal: Modal<WifiMessage> = Modal::new(self.settings, password_modal, {
            Container::new(
                Card::new(Text::new("Settings"),Row::new()
                    .push(Column::new()
                        .push(Button::new("Cancel")
                            .on_press(WifiMessage::OpenSettings(false, "".to_string()))
                        )
                        .align_items(iced::Alignment::Center)
                        .width(Length::Fill)
                    )
                    .push(Column::new()
                        .push(Button::new("Forget")
                            .on_press(WifiMessage::Forget(self.ssid.clone()))
                        )
                        .align_items(iced::Alignment::Center)
                        .width(Length::Fill)
                    )
                ).style(CardStyles::Primary)
            )
            .width(Length::Fixed(400.0))
            .center_x()
            .center_y()
        }
        )
        .on_esc(WifiMessage::OpenSettings(false, "".to_string()))
        .backdrop(WifiMessage::OpenSettings(false, "".to_string()))
        .into();

        let password_show_modal: Modal<WifiMessage> = Modal::new(self.show_password, settings_modal, {
            Container::new(
                Card::new(Text::new("Info"),Column::new()
                    .align_items(iced::Alignment::Center)
                    .spacing(10)
                    .push(Row::new()
                        .spacing(10)
                        .align_items(iced::Alignment::Center)
                        .push(Text::new(format!("SSID: {}",self.ssid)))
                        .push(Button::new(Text::new('\u{f0c5}'.to_string())
                            .font(Font::with_name("Font Awesome 6 Pro Light"))
                            )
                            .on_press(WifiMessage::Copy(self.ssid.clone()))
                        )
                    )
                    .push(Row::new()
                        .spacing(10)
                        .align_items(iced::Alignment::Center)
                        .push(Text::new(format!("Security: {}",self.security)))
                        .push(Button::new(Text::new('\u{f0c5}'.to_string())
                            .font(Font::with_name("Font Awesome 6 Pro Light"))
                            )
                            .on_press(WifiMessage::Copy(self.security.clone()))
                        )
                    )
                    .push(Row::new()
                        .spacing(10)
                        .align_items(iced::Alignment::Center)
                        .push(Text::new(format!("Password: {}",self.password_str)))
                        .push(Button::new(Text::new('\u{f0c5}'.to_string())
                            .font(Font::with_name("Font Awesome 6 Pro Light"))
                            )
                            .on_press(WifiMessage::Copy(self.password_str.clone()))
                        )
                    )
                    .push(
                        if let Some(qr_code_data) = &self.qr_code {
                            Container::new(QRCode::new(qr_code_data).color(BLACK, LIGHT).cell_size(16))
                        } else {
                            Container::new(Text::new("QR Code Not Available"))
                        }
                    )
                    .push(Button::new("Close").on_press(WifiMessage::ShowPassword(false)))
                    .width(Length::Fill)
                
                ).style(CardStyles::Primary)
            )
            .width(Length::Fixed(600.0))
            .center_x()
            .center_y()
        }
        )
        .on_esc(WifiMessage::ShowPassword(false))
        .backdrop(WifiMessage::ShowPassword(false))
        .into();

        let bluetooth_settings: Modal<WifiMessage> = Modal::new(self.bluetooth_settings, password_show_modal, {
            Container::new(
                Card::new(Text::new("Settings"),Row::new()
                    .push(Column::new()
                        .push(Button::new("Cancel")
                            .on_press(WifiMessage::SettingsBluetooth(false, [0,0,0,0,0,0]))
                        )
                        .align_items(iced::Alignment::Center)
                        .width(Length::Fill)
                    )
                    .push(Column::new()
                        .push(Button::new("Forget")
                            .on_press(WifiMessage::RemoveBluetooth)
                        )
                        .align_items(iced::Alignment::Center)
                        .width(Length::Fill)
                    )
                ).style(CardStyles::Primary)
            )
            .width(Length::Fixed(400.0))
            .center_x()
            .center_y()
        }
        )
        .on_esc(WifiMessage::SettingsBluetooth(false, [0,0,0,0,0,0]))
        .backdrop(WifiMessage::SettingsBluetooth(false, [0,0,0,0,0,0]))
        .into();

        iced::Element::new(bluetooth_settings)
    }
}

fn is_wifi_enabled() -> bool {
    let output: Output = Command::new("nmcli")
        .arg("radio")
        .arg("wifi")
        .output()
        .expect("Failed to execute nmcli command.");

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.contains("en") {
        true
    } else {
        false
    }
}

#[derive(Debug)]
struct Pair {
    ssid: String,
    in_use: String,
}

fn get_networks() -> Vec<Pair> {
    let command_output = Command::new("nmcli")
    .args(&["-t", "-e", "no", "-f", "SSID,IN-USE", "device", "wifi"])
        .output()
        .expect("Failed to execute command");

    let output_str = String::from_utf8_lossy(&command_output.stdout);
    let mut pairs: Vec<Pair> = Vec::new();

    for line in output_str.lines() {
        let fields: Vec<&str> = line.rsplitn(2, ':').collect();
        if fields.len() >= 2 {
            let ssid = fields[1].trim().to_string();
            let in_use = fields[0].trim().to_string();
            let pair = Pair { ssid, in_use };
            pairs.push(pair);
        }
    }
    pairs
}

fn connect_to_network(ssid: &str, password: &str) {
    let command = format!("nmcli device wifi connect {} password {}", ssid, password);

    if let Ok(output) = Command::new("sh")
        .arg("-c")
        .arg(&command)
        .output()
    {
        if !output.status.success() {
            eprintln!("Failed to connect to network: {}", ssid);
            _ = Command::new("nmcli").args(&["connection", "delete", ssid]).output();
        }
    } else {
        eprintln!("Failed to execute nmcli command.");
    }
}

fn disconnect_network(ssid: &str) {
    let command = format!("nmcli connection down {}",ssid);
    if let Ok(output) = Command::new("sh")
        .arg("-c")
        .arg(&command)
        .output()
    {
        if !output.status.success() {
            eprintln!("Failed to disconnect network: {}", ssid);
        }
    } else {
        eprintln!("Failed to execute nmcli command.");
    }
}

fn connect_to_known_network(ssid: &str) {
    let command = format!("nmcli connection up {}", ssid);
    if let Ok(output) = Command::new("sh")
        .arg("-c")
        .arg(&command)
        .output()
    {
        if !output.status.success() {
            eprintln!("Failed to connect to network");
        }
    } else {
        eprintln!("Failed to execute nmcli command.");
    }
}

fn show_password() -> (String,String,String) {
    let output = match Command::new("nmcli")
        .args(&["-t", "device", "wifi", "show-password"])
        .output() {
            Ok(output) => output,
            Err(e) => {
                eprintln!("Error running command: {}", e);
                return ("".to_string(),"".to_string(),"".to_string());
            }
        };

    if !output.status.success() {
        eprintln!("Command execution failed: {:?}", output);
        return ("".to_string(),"".to_string(),"".to_string());
    }

    let output_str = String::from_utf8_lossy(&output.stdout);

    let mut ssid = String::new();
    let mut security = String::new();
    let mut password = String::new();

    for line in output_str.lines() {
        let mut fields = line.splitn(2, ':');
        if let (Some(field_name), Some(field_value)) = (fields.next(), fields.next()) {
            let field_name = field_name.trim();
            let field_value = field_value.trim();

            match field_name {
                "SSID" => ssid = field_value.to_string(),
                "Security" => security = field_value.to_string(),
                "Password" => password = field_value.to_string(),
                _ => {},
            }
        }
    }
    (ssid,security,password)
}

async fn bluetooth_adapter() -> Result<Adapter, Box<dyn Error>> {
    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;
    Ok(adapter)
}


async fn is_bluetooth_enabled(adapter: &Adapter) -> bool {
    match adapter.is_powered().await {
        Ok(is_powered) => is_powered,
        Err(_) => false,
    }
}

async fn able_bluetooth(adapter: &Adapter, value: bool) {
    adapter.set_powered(value).await.expect("Error changing bluetooth power");
}

#[derive(Debug)]
struct BluetoothDeviceInfo {
    addr: Address,
    name: Option<String>,
    paired: bool,
    connected: bool,
    trusted: bool,
}

async fn query_device_info(adapter: &Adapter, addr: Address) -> bluer::Result<BluetoothDeviceInfo> {
    let device = adapter.device(addr)?;
    let name = device.name().await?;
    let paired = device.is_paired().await?;
    let connected = device.is_connected().await?;
    let trusted = device.is_trusted().await?;

    Ok(BluetoothDeviceInfo {
        addr,
        name,
        paired,
        connected,
        trusted,
    })
}

async fn discover_bluetooth_devices(adapter: &Adapter) -> Result<Vec<BluetoothDeviceInfo>, Box<dyn Error>> {
    let with_changes = env::args().any(|arg| arg == "--changes");
    let filter_addr: HashSet<_> = env::args().filter_map(|arg| arg.parse::<Address>().ok()).collect();
    let device_events = adapter.discover_devices().await?;
    pin_mut!(device_events);

    //let mut all_change_events = SelectAll::new();
    let mut devices: Vec<BluetoothDeviceInfo> = Vec::new();

    /*loop {
        tokio::select! {
            Some(device_event) = device_events.next() => {
                match device_event {
                    AdapterEvent::DeviceAdded(addr) => {
                        if !filter_addr.is_empty() && !filter_addr.contains(&addr) {
                            continue;
                        }

                        println!("Device added: {:?}", addr);
                        let device_info = query_device_info(&adapter, addr).await?;
                        devices.push(device_info);

                        if with_changes {
                            let device = adapter.device(addr)?;
                            let change_events = device.events().await?.map(move |evt| (addr, evt));
                            all_change_events.push(change_events);
                        }
                    }
                    AdapterEvent::DeviceRemoved(addr) => {
                        println!("Device removed: {:?}", addr);
                        devices.retain(|dev| dev.addr != addr);
                    }
                    _ => (),
                }
                println!();
            }
            Some((addr, DeviceEvent::PropertyChanged(property))) = all_change_events.next() => {
                println!("Device changed: {:?}", addr);
                println!("    {:?}", property);
            }
            _ = sleep(Duration::from_secs(2)) => {
                // Timeout triggered before completing the loop
                println!("Timeout! Exiting...");
                break; // Exit the loop when the timeout occurs
            }
            else => break
        }
    }*/
    Ok(devices)
}

fn print_bluetooth_devices(devices: &[BluetoothDeviceInfo]) {
    for device in devices {
        println!("Device Address: {:?}", device.addr);
        if let Some(name) = &device.name {
            println!("Device Name: {}", name);
        } else {
            println!("Device Name: N/A");
        }
        println!("Paired: {}", device.paired);
        println!("Connected: {}", device.connected);
        println!("Trusted: {}", device.trusted);
        println!();
    }
}

async fn pair_device(device: Device) {
    match device.pair().await {
        Ok(()) => println!("Device paired"),
        Err(err) => println!("Device pairing failed: {}", &err),
    }
}

async fn connect_device(device: Device) -> Result<(), bluer::Error> {
    if !device.is_connected().await? {
        let mut retries = 2;
        loop {
            match device.connect().await {
                Ok(_) => break,
                Err(_) if retries > 0 => {
                    retries -= 1;
                }
                Err(err) => { eprintln!("Error connecting"); return Err(err.into())},
            }
        }
    }
    Ok(())
}


async fn disconnect_device(device: Device) {
    match device.disconnect().await {
        Ok(()) => println!("Device disconnected"),
        Err(err) => println!("Device disconnection failed: {}", &err),
    }
}

async fn remove_device(adapter: &Adapter, address: [u8; 6]) {
    if adapter.remove_device(bluer::Address(address)).await != Ok(()) {
        eprintln!("Error removing device");
    }
}