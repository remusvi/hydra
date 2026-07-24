// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] //lil note from the tauri devs


fn main() {
    hyrda_lib::run()
}
