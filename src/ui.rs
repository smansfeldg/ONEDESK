use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        #[cfg(feature = "appimage")]
        let prefix = std::env::var("APPDIR").unwrap_or("".to_string());
        #[cfg(not(feature = "appimage"))]
        let prefix = "".to_string();
        #[cfg(feature = "flatpak")]
        let dir = "/app";
        #[cfg(not(feature = "flatpak"))]
        let dir = "/usr";
        sciter::set_library(&(prefix + dir + "/lib/rustdesk/libsciter-gtk.so")).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        crate::using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String, test_with_proxy: bool) -> String {
        test_if_valid_server(host, test_with_proxy)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn http_request(&self, url: String, method: String, body: Option<String>, header: String) {
        http_request(url, method, body, header)
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn get_http_status(&self, url: String) -> Option<String> {
        get_async_http_status(url)
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn has_vram(&self) -> bool {
        has_vram()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn default_video_save_directory(&self) -> String {
        default_video_save_directory()
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }

    fn has_valid_2fa(&self) -> bool {
        has_valid_2fa()
    }

    fn generate2fa(&self) -> String {
        generate2fa()
    }

    pub fn verify2fa(&self, code: String) -> bool {
        verify2fa(code)
    }

    fn generate_2fa_img_src(&self, data: String) -> String {
        let v = qrcode_generator::to_png_to_vec(data, qrcode_generator::QrCodeEcc::Low, 128)
            .unwrap_or_default();
        let s = hbb_common::sodiumoxide::base64::encode(
            v,
            hbb_common::sodiumoxide::base64::Variant::Original,
        );
        format!("data:image/png;base64,{s}")
    }

    pub fn check_hwcodec(&self) {
        check_hwcodec()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String, bool);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn has_vram();
        fn get_langs();
        fn default_video_save_directory();
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
        fn has_valid_2fa();
        fn generate2fa();
        fn generate_2fa_img_src(String);
        fn verify2fa(String);
        fn check_hwcodec();
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAACXBIWXMAAAsSAAALEgHS3X78AAAQwElEQVR4nO2dX2xTV57HvwnJpCbYDmYXNTGZAJsYqQskjSuiWVj5MvNEiUW20mgmntU2fViHzEOJGh7ow4rLU/vQSOGlNH4hlYrzRBUUApp54XpgtVOmSfOnsxKGUTNpC0uXem3s1BOS2vvg3DTE998599w/Se9HikR97zn3VL/v/Z3f+Z0/t6JYLIKCvQC41b82AK00lTjoZgbANABh9W+etIIKQgFwAPoBnCJ9kIMpXAMwhJIYNKFVABwAHkCIolEO5pNAyV6C2o2VKtfrUFLULTjG30yEULLZEEo2lEXJA9ShpCCnf9/czKDkwdNSF+U8QBtKAYVj/M1PK0q2bJO6KOUB6lYLeI1slYPpZFAavT3nCTZ6ANHtO8bfenhRsu1zMcFGAfBw3P5WphUlG6+xvgvgUIocHbY+x7E6RFzvAXgrWuJgCbz4D1EAHJxxvu0opDNGVR1CyeaoWv2h36gnOaizPD2H78YmsCTcxvL0HAqZp89dr/R6UMMdg6urE7U9EVaP7QcgVBSLxb0AvmBVq4M2VuYXsDgSx3cjV7Dy1y81l6tqakTd0LtwdZ1k0Yx9FcVisQfAZRa1OaizMr+Ap/w7WPxwVFc9ta93wzdySW9z3qjCal/gYCyFdAZP+XeQvfgBk/pEAekUAVcJmRShAzsWR+J4tPcQM+Ov1fvhKDL8u3qqaKsoUq4IcVBnZX4BqZ4+LCX+09Dn1H8xi6q9P6UqqzYd7EBJfmwCj9uOGW58AHjKv0Nd1vEABpDuP8fc3atB6wUcD8CQQjqD/2k7ZrrxASA39D5VOUcAjFiensPjtmNYnvnckuf/TbhDVc4RAAOWhDv4hjtJlNBhzfLM51iZXyAu5whAJ4sjcXxzvLMsfWsFy9NzxGUcAehgcSSO1Bu/tboZazxzBGAedjM+AHw//1fiMo4AKLCj8QE4MYAZ2NX4tDgCIGCrGR9wBKCZJeHOljM+4AhAE8vTc3jSxWwljq1wBKBCIZ3BN9xJW4zzjcARgAJb3fiAIwBFUj19luX2zcIRgAwZ/l3kr92wuhlEVNaR7+hzBCBBfmwCTy/oWmplCdVth4nLOALYgLiM68dClfotPy6edEUMCfpcp15FddthvMAdA1AS2pJwG/mxCWbPE+smwTABPHz4EIIgQBAEJJNJ5HK5snva29tx4MABBAIBcBwHt9ttVHM0ke4/xzToq2pqhId/G66uk2X9cw2A2p4ICukMUj19TOKNbRRLwpivCZycnMTw8DCmpqaIy4ZCIXAch3A4zLJJmsiPTeDJv/yGSV2i4Um2caV6+nRvFmksSp4CowgzAWSzWcRiMYyO6vufAIAdO3YgEomgu7vbFK9QSGfwaO8hJq7Yc/4c3P19xBF5IZ3B47Zj1KuKakJHsVuYIC7HJAjMZrPo7e1lYnwAyOVyiMViCIfDiMViyGazTOqVg0W/X916EC9+dhte/hzdcKzOCw//NvXzf9J2iKqcbgGIxk8mk3qrKkMUQiQSgSAIzOsHgOzQJd1r92tf78ZuYQLVlEYQcXWdRKXXQ1WWZggIMOgCotEoVX9PQygUAs/zzLqFlfkFPG47puvt911+n+WWbTzpilAFhC9+dptKgLo8QDweN834AJBIJBAOhzE5OcmkvlRPH7XxK70e7L51nanxAcpkjtdD7X2oBSAGfWaTy+XQ29ur+9l6XH+l14PdwgRqKMbdatCM5fW0g1oAsVhMcmxvFrFYDAMDA1QBorhHn4bq1oNM+nuW1HD/TF2WKgbIZrMIh8OWCkAkEAhgeHiYKC6g7WdF49NE+VoppDP4emcTURnTdwcLgmAL4wNAMplEOBzWPArJj03Y1vgA+YxeVVMjtfEBHQKwE7lcDtFoVFUEhXQG6f5zxPVXej3YNXLJcOPToPesICoBJBIJXQ81Ai0iyA5dIs60iQGfWX0+6fYuV1enrucRC4DVEMwIlESwMr9ANcdvdsBHcjageHycHogFcO/ePV0PNBpRBA8fPnzudxrX77v8vq2i/Y2wOCqOWAB2Cf6UyOVyOHv27NoQcUm4Qxz4uc+cZp7k0QLJPn+97h+gEMCnn36q+6FmkEwmMTAwAADIEI75XadeRd2QvZeEVTU1WuMBNhNTU1O48pseooxfVVMjiwMYqVkSbmu6j9FJoVtbAADw2e6d+HP7QU33Vno9+LuxuKXDPa2jgNoeRotXmNRCSWdnJziOQzAYfC6TNzk5iXv37mFyclLXkLOxsRHPvv8eN4624++/fIjd/5tSvN/Dv21p0Lcyv6Bpcqq69SCzdloigFAohIGBATQ0NEheDwaDCAaDiEQiyGazEAQBsVgMjx49InrO/v37sby8DAC4FjmFf/vgCmqWnkne6zr1Ktz91q4G1vr2u/vZbVI1vQvo7OzE4OCgrPE34na7EQ6HMT4+jvPnz6O+vl5TucbGxjXjA0C68D3+6+TPJe+t9Hos7fdFtPT/lV4Ps/4fMFkAnZ2d4Hmeunw4HEY8Hkc0GlW9d9++fWW//cm/G385eKDsd6v7fREtQ0CpFcZ6ME0A9fX1a8MyPbjdbkSjUcTjcVlv4PV6sbKyInntxi9+hqWan/xQ35nThszrk1JIZzQtSdezblAK0wQQjUaZrvANBAKIx+Po7CxPhrz88suy5f5WKED4ZcmFisu37UB+TH1Fb03oqK6ZPymIBfDKK68QP6S+vt6Qtf5utxs8z+Ott95a+62mpgbPnkkHeiKzO9340v8i6obetYXrB4D82HXVe7wGiNUUD8BxnKH1RyIRnD9/HgDw0ksvaSrzu3/tYhpM6WVJpf+vamo0pKsiFkAwGCR+iNECAEoB4vDwMDwebcuq/++773Dz5k2DW6UNLfsDjeqqiAWgdRi2HhrR0LCysvLc0E8NQRCQz+cNbJE21Nx/VVOjYRNTxAJoaGjAjh07NN9PIxhaPvnkE6L78/k8rl69alBrtFFIZ1T3BBoZqFLFAIFAQPO9ZgkglUrhwYMHxOXu3r2LVEo5RWwkatG/kW8/QCkAmpGA0ehZp2ilF1gcuaJ43ehhKpUAzOrTSZidnaUuOzc3h/v37zNsjTZW5hcUp6qNfvuBLSKA2dlZ3W7cipXOaptTzEhSUecBQiH7fGta7e3nOA4+n0/xnrm5OVNjgUI6o9j/m/H2AzoEYMbYXitzc8rTqBzH4cSJE6r13Lhh3rFwiyNxxbG/WbOT1ALQ2g2QzuGTMjs7qziWP3LkCHw+Hzo6OuD3+xXrunv3rml5AaWvfNWEjpo2QUUtgIaGBk3DQTMEoMTx48fX/v3aa6+p1keaS6BhcSSuuEFlp4kLUnXNBXR3d2u6z4jTQ0SU3L/f73/urW9paUFzc7NifWYEg0rBn/vMaVOXpekSgNY4wKjNJGruX6p9arFAKpUydEiYH5uQffsrvR7Tp6d1CcDtdkvOx2/EKA+glPlzuVzo6Ogo+12LFzCyG1Dao+Dh3zZ9elr3dLCWeX6j9hMq9f9SxhdR8wJqowpaFkfisqt+qlsPWrIoVbcAgsGgajCYTCaZH/WWSqUUx+1K3VNLS4tiXiCfz+vKLMqh1PfvsmhRKpMFIVqCQdbBlZKB/H6/auJHzQvQTCwpoRT5mx34rYeJAMLhsOqsH2sBKAVqWoLTjo4OuFwu2essPYDSwRRWr0tktiRMbal2IpFg2g0ovaGHD2s7ak1JKGpdDAnZoUuyWT+fxSePMBMAx3GqC0VYeYFUKiU7/Dty5Ijim70epUARUPYyWlE6mMIOS9KZCcDtdquu+x8fH2fyLCXDaH37AcDn8+HQIfm+9+uvvyZqlxRyH5+w2vWLMF0VrBYLTE1NlZ3cQYOcYVwuF5EAAGUv8NVXXxHVtZH82ITsfL/Vrl+E+bJwNS/A4nRROcOoJXikOHz4sGyXoWckIH4IQgrP+XOWu34R5gLgOA7t7e2y169fv647GJQzDOnbL6LUDdAGgk/5dyQDv+rWg/Dy5OcVGYUhG0POnj2reF3PdwWUDNLS0kJVp5Jwvv32W+L6loQ7yF78oOx38QAKO2GIAAKBgGJyKB6PU3sBOYP4fD7V5I8cSgIg9QBKrt83con53j69GLY1LBqNygaE4ocgaJBz/2qLPdSQix9IBZDq6ZPM+LnPnLbVVjQRwwQgbtyUY3R0lMmIQGTPnj2WlgdK6V6p4+iqWw/a9tQxQzeHBoNBxa5gcHCQuE65HADNCGA9ct2H1iViK/MLkule8ahZu2L47uBoNCo7W5hIJJhNFe/atUtXebkuREsuoJDOyH54yowTxvVguADErkAuTczzPJM5AtoAkAVyH5y0+1GzgEnnAwQCAdkE0aNHj4gCQqkgkIXxt2/fTlVucSQuubnTqqNmSTHtiJhwOCy7fGx0dFTXRBELAch1AUoTS0vCHaTeKD+yrfb1btsGfRsx9ZQwnudl4wGe55mOClghNzpYnp7Dk67yN9zOEb8Upp8TODw8LJkf2HjCNwm0GcD1kIz3C+kMvpX45JxZn5VhiekCcLvdGBwclAwKk8kk1dCQBUoZxvUU0hl8w50sC/o2o/EBiw6LDgQCiMVikiK4fv26YlBodrS//nlyxq9qatyUxgcsPC1cSQSxWEx28YhRApBbY7C+e0n19JUZ3w4njOvB0uPilURw4cIFzSuI9C7cAKRjAHFkICZ6NqZ57fgRSVIs/14AqQikAj4WO3qlUswtLS1rbn8rGh+wgQAAMhFIdQF6V+/m83nJLuAf6hu2VMAnhS0EAPwgAqk8wYULF9ZGB1IeQGmVsBak9gDs3LEDu7v/vcz4rlOvbhnjAzYSAPDDd4CllpSNjo5iYGAA1dXVklk7PRs5pLKQ/zj5edm8vvvM6U0d8ElhKwEApTxBLBaTnEZOJBLo7e3F/v37y67R7ui9f/9+mft/Yds2tCf+uPbflV4PfJff31QZPq3YTgAiAwMDeO+998rigmQyiaGhobL7Hzx4QLyRI5/P48qV8nP6Xvnvv6x9Wkbs7zfDxA4NthUAUFphPD4+XnYi2dLSkmSf//HHHxPFAlevXi0LIF9EJX72+z8AKLn8rRDpK1FRLBanAbRa3RA1BEHA4ODg2plDVVVVOHr0aNnh0H6/H2+++abiLF4+n8dHH31Udg7AC9u24VdXrqFhey18I5dss3bfQGYqisXiCIDXrW6JFrLZLEZHRxGPx5HL5VBbW4tgMFj2eRifz4cTJ06UbfpIpVKYnZ3FzZs3yzyFaPzm30bh7u/bUoGeAh9WFIvFHgCXrW4JCeuFUCwWJUUg4nK54Pf7FXf51FVuw6+zSwj8xznbLds2mDcqisXiXgBfWN0SWsbHx3Hr1i08e/YMlZVkIc0LNTX4p+1u/CLSDfcB/VPKm5B9FcViEQDGAJyyuDG6yGazGB8fx/z8PIrFIh4/fix5X3NzM/bs2YPm5mbqrWRbhGsAukQBcABuWdocB7M5DkAQfaYAgP4jvQ6bjQRKNn8uD8Bb0RIHS+DFf6wXgADgotktcTCdi1h9+4FSImj9xbrVi7ZPDDlQMYNSvJcWf9goAKAkgnkAP4pMyI+IDIC9WGd8QHouII2SSjKGN8nBLDLY8OaLyGVOplFSy4xhTXIwixmUbDktdVEpdSZ6Aicw3LxcBNAGiTdfRC13mgbQj1LSwMkTbB4SKNmsX+1GqSBQCW610k2dNt7CXAMwhHXDPDVIBSCyFyUxcCi5GGfYaA0zKPXtwurfPGkF/w8tBcxFABZ+IAAAAABJRU5ErkJggg==".into()
    }
}
