/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

//! This crate allows to easily develop Rust plugins for [Tranalyzer2](https://tranalyzer.com/), a
//! network traffic analysis tool.
//!
//! An example Rust plugin for Tranalyzer2 using this crate can be found here:
//! https://github.com/Tranalyzer/rustExample
//!
//! # Create a new plugin
//!
//! 1. [Download](https://tranalyzer.com/getit) and [install](https://tranalyzer.com/install)
//!    Tranalyzer2.
//!
//! 2. Clone the Tranalyzer2 Rust plugin template and rename it.
//!
//!    ```sh
//!    cd $T2HOME
//!    git clone https://github.com/Tranalyzer/rustTemplate.git myPluginName
//!    cd myPluginName
//!    ./autogen.sh --rename
//!    ```
//!
//! 3. Optional: change the `PLUGINORDER` at the top of `autogen.sh`.
//!
//! 4. Fill the different methods of the [`T2Plugin`](trait.T2Plugin.html) trait implementation in
//! `src/lib.rs`.

extern crate libc;

/// Contains the definition of a [`Flow`](nethdr/struct.Flow.html), a
/// [`Packet`](nethdr/struct.Packet.html) and the different protocol headers.
pub mod nethdr;
/// Contains the [`SliceReader`](slread/struct.SliceReader.html) which allows to easily read
/// integers and strings from a byte slice.
pub mod slread;

use nethdr::{Packet, Flow};
use libc::c_char;
use std::mem;
use std::iter::Product;
use std::ops::Div;
use std::ffi::CString;

/// `unsigned long` in C: `u32` on 32-bit systems and `u64` on 64-bit systems.
#[allow(non_camel_case_types)]
#[cfg(target_arch = "x86_64")]
pub type c_ulong = u64;
#[allow(non_camel_case_types)]
#[cfg(target_arch = "x86")]
pub type c_ulong = u32;

/// `flow_index` value representing a non-existing [`Flow`](nethdr/struct.Flow.html).
#[cfg(target_arch = "x86_64")]
pub const HASHTABLE_ENTRY_NOT_FOUND: c_ulong = std::u64::MAX;
#[cfg(target_arch = "x86")]
pub const HASHTABLE_ENTRY_NOT_FOUND: c_ulong = std::u32::MAX;

/// Rust opaque representation of `binart_valut_t` struct from Tranalyzer2
pub enum BinaryValue {}
/// Rust opaque representation of `outputBuffer_t` struct from Tranalyzer2
pub enum OutputBuffer {}

/// Types of values which can be outputted in Tranalyzer2 flow files.
///
/// Enum copied from `tranalyzer2/src/binaryValue.h`. These types describe the types of values
/// outputted in Tranalyzer2 columns. They are used when building a [`Header`](struct.Header.html)
/// in the [`print_header`](trait.T2Plugin.html#method.print_header) method.
#[repr(u32)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum BinaryType {
    bt_compound = 0,
    // all signed integers
    bt_int_8 = 1,
    bt_int_16,
    bt_int_32,
    bt_int_64,
    bt_int_128,
    bt_int_256,
    // all unsigned integers
    bt_uint_8,
    bt_uint_16,
    bt_uint_32,
    bt_uint_64, // = 10
    bt_uint_128,
    bt_uint_256,
    // hex values
    bt_hex_8,
    bt_hex_16,
    bt_hex_32,
    bt_hex_64,
    bt_hex_128,
    bt_hex_256, // 32 bytes
    // floating point
    bt_float,
    bt_double, // = 20
    bt_long_double,
    // char and string
    bt_char,
    bt_string,
    // now the special types
    bt_flow_direction,
    bt_unix_time,   // the time struct consists of one uint_64 value for the seconds
                    // and a uint_32_t value for the nanosecs
    bt_time,        // this is the same than above, but rather than unix_time, this
                    // type is for time data where it makes no sense to calculate an
                    // absolute date (e.g. time durations) but where a textual output
                    // could be changed e.g. from seconds to minutes or hours.
    bt_mac_addr,
    bt_ip4_addr,
    bt_ip6_addr,
    bt_string_class,
}

// access to C functions and variables exported by the Tranalyzer2 core
extern {
    static mainHashMap: *const HashTable;
    static flows: *mut Flow;
    static main_output_buffer: *mut OutputBuffer;
    fn bv_append_bv(dst: *mut BinaryValue, new: *mut BinaryValue) -> *mut BinaryValue;
    fn bv_new_bv(name_long: *const c_char, name_short: *const c_char, repeating: u32, count: u32, ...) -> *mut BinaryValue;
    fn outputBuffer_append(buffer: *mut OutputBuffer, output: *const c_char, size: usize);
    fn outputBuffer_append_str(buffer: *mut OutputBuffer, output: *const c_char);
}

/// Returns the number of flows that Tranalyzer2 can store in its internal hashtable.
///
/// Corresponds to Tranalyzer2 internal `mainHashMap->hashChainTableSize` value.
pub fn hashchaintable_size() -> usize {
    unsafe {
        (*mainHashMap).hashchaintable_size as usize
    }
}

/// Returns the [`Flow`](nethdr/struct.Flow.html) structure of the flow with `flow_index=index`.
///
/// Corresponds to Tranalyzer2 internal `flows[index]`.
///
/// # Example
///
/// ```
/// use t2plugin::{getflow, HASHTABLE_ENTRY_NOT_FOUND};
/// use t2plugin::nethdr::Flow;
///
/// fn get_opposite_flow<'a>(flow: &'a Flow) -> Option<&'a mut Flow> {
///     match flow.opposite_flow_index {
///         HASHTABLE_ENTRY_NOT_FOUND => None,
///         index => Some(getflow(index)),
///     }
/// }
/// ```
pub fn getflow<'a>(index: c_ulong) -> &'a mut Flow {
    unsafe {
        &mut *(flows.offset(index as isize))
    }
}

/// Appends a string to Tranalyzer2 output buffer.
///
/// This function can be called in the
/// [``on_flow_terminate``](trait.T2Plugin.html#method.on_flow_terminate) method to append a
/// string to the output flow file.
///
/// # Example
///
/// ```
/// struct HttpPlugin {
///     ...
///     host: String,
/// }
///
/// impl T2Plugin for HttpPlugin {
///     ...
///     #[allow(unused_variables)]
///     fn on_flow_terminate(&mut self, flow: &mut Flow) {
///         // output the HTTP host in a bt_string column
///         output_string(&self.host);
///     }
/// }
/// ```
pub fn output_string<T: AsRef<str>>(string: T) {
    let cstring = CString::new(string.as_ref()).unwrap().into_raw();
    unsafe {
        outputBuffer_append_str(main_output_buffer, cstring);
    }
}

/// Appends a list of strings to Tranalyzer2 output buffer.
///
/// This function can be called in the
/// [``on_flow_terminate``](trait.T2Plugin.html#method.on_flow_terminate) method to append a
/// repetitive string field to the output flow file.
///
/// # Example
///
/// ```
/// struct HttpPlugin {
///     ...
///     cookies: Vec<String>,
/// }
///
/// impl T2Plugin for HttpPlugin {
///     ...
///     #[allow(unused_variables)]
///     fn on_flow_terminate(&mut self, flow: &mut Flow) {
///         // output the HTTP cookies in a repetitive bt_string column
///         output_strings(&self.cookies);
///     }
/// }
/// ```
pub fn output_strings<T: AsRef<str>>(strings: &[T]) {
    output_num(strings.len() as u32);
    for string in strings {
        let cstring = CString::new(string.as_ref()).unwrap().into_raw();
        unsafe {
            outputBuffer_append_str(main_output_buffer, cstring);
        }
    }
}

/// Appends a number (integer or float) to Tranalyzer2 output buffer.
///
/// This function can be called in the
/// [``on_flow_terminate``](trait.T2Plugin.html#method.on_flow_terminate) method to append a
/// number to the output flow file.
///
/// # Example
///
/// ```
/// impl T2Plugin for ExamplePlugin {
///     ...
///     #[allow(unused_variables)]
///     fn on_flow_terminate(&mut self, flow: &mut Flow) {
///         // output the flow index in a bt_uint_64 column
///         output_num(flow.findex);
///     }
/// }
/// ```
pub fn output_num<T: Product + Div>(val: T) {
    let size = mem::size_of::<T>();
    let ptr = &val as *const T;
    unsafe {
        outputBuffer_append(main_output_buffer, ptr as *const c_char, size);
    }
}

/// Appends a list of numbers (integers or floats) to Tranalyzer2 output buffer.
///
/// This function can be called in the
/// [``on_flow_terminate``](trait.T2Plugin.html#method.on_flow_terminate) method to append a
/// repetitive number field to the output flow file.
///
/// # Example
///
/// ```
/// struct HttpPlugin {
///     ...
///     status_codes: Vec<u16>,
/// }
///
/// impl T2Plugin for HttpPlugin {
///     ...
///     #[allow(unused_variables)]
///     fn on_flow_terminate(&mut self, flow: &mut Flow) {
///         // output flow HTTP status codes in a repetitive bt_uint_16 column.
///         output_nums(&self.status_codes);
///     }
/// }
/// ```
pub fn output_nums<T: Product + Div>(vals: &[T]) {
    output_num(vals.len() as u32);
    let size = mem::size_of::<T>();
    for val in vals {
        let ptr = val as *const T;
        unsafe {
            outputBuffer_append(main_output_buffer, ptr as *const c_char, size);
        }
    }
}

/// Appends bytes to Tranalyzer2 output buffer.
///
/// This function can be called in the
/// [``on_flow_terminate``](trait.T2Plugin.html#method.on_flow_terminate) function to append
/// raw bytes in Tranalyzer2 output buffer. This can be used to output types which are neither a
/// string, nor a number (e.g. MAC or IP addresses).
///
/// # Example
///
/// ```
/// impl T2Plugin for ExamplePlugin {
///     ...
///     #[allow(unused_variables)]
///     fn on_flow_terminate(&mut self, flow: &mut Flow) {
///         // output flow source IPv6 address in a bt_ip6_addr column
///         match flow.src_ip6() {
///             Some(ip) => output_bytes(&ip.octets()),
///             None => output_bytes(&[0u8; 16]),
///         }
///     }
/// }
/// ```
pub fn output_bytes(val: &[u8]) {
    let ptr = val as *const [u8];
    let size = val.len();
    unsafe {
        outputBuffer_append(main_output_buffer, ptr as *const c_char, size);
    }
}

/// Trait to tranform a per flow `struct` into a Tranalyzer2 plugin.
///
/// The [`t2plugin!`](macro.t2plugin.html) macro can transform any `struct` implementing this
/// trait into a Tranalyzer2 plugin.
pub trait T2Plugin {
    /// Creates a new per flow plugin structure with default values.
    ///
    /// This function is called when Tranalyzer2 creates a new flow
    fn new() -> Self;

    /// Returns a list of other plugins which are required by this plugin.
    ///
    /// # Example
    ///
    /// ```
    /// impl T2Plugin for ExamplePlugin {
    ///     ...
    ///     fn get_dependencies() -> Vec<&'static str> {
    ///         // this plugin cannot run if "tcpFlags" and "httpSniffer" are not loaded
    ///         vec!["tcpFlags", "httpSniffer"]
    ///     }
    /// ```
    fn get_dependencies() -> Vec<&'static str> { vec![] }

    /// This method is called once when Tranalyzer2 starts.
    ///
    /// Plugin specific global variables and files should be created/opened here.
    fn initialize() {}

    /// Returns a [`Header`](struct.Header.html) describing the columns outputted by this plugin.
    ///
    /// # Example
    ///
    /// ```
    /// impl T2Plugin for ExamplePlugin {
    ///     ...
    ///     fn print_header() -> Header {
    ///         let mut header = Header::new();
    ///         header.add_simple_col("IPv4 source address", "srcIP4", false, BinaryType::bt_ip4_addr);
    ///         header.add_simple_col("HTTP cookies", "httpCookies", true, BinaryType::bt_string);
    ///         header
    ///     }
    /// }
    /// ```
    fn print_header() -> Header { Header::new() }

    /// Called on the first seen packet of a flow.
    ///
    /// This method is called right after the per flow `struct` of this plugin is created with the
    /// [`new`](trait.T2Plugin.html#method.new) method.
    #[allow(unused_variables)]
    fn on_flow_generated(&mut self, packet: &Packet, flow: &mut Flow) {}

    /// Called on each packet which has a layer 2 header.
    ///
    /// The `plugin` and `flow` parameters contain `Some` data only if `ETH_ACTIVATE` (Ethernet
    /// flows) is activated in Tranalyzer2. Otherwise they are `None` and only the `packet`
    /// contains useful information.
    #[allow(unused_variables)]
    fn claim_l2_info(packet: &Packet, plugin: Option<&mut Self>, flow: Option<&mut Flow>) {}

    /// Called on each packet which has a layer 3 header.
    #[allow(unused_variables)]
    fn claim_l3_info(packet: &Packet) {}

    /// Called on each packet which has a layer 4 header.
    #[allow(unused_variables)]
    fn claim_l4_info(&mut self, packet: &Packet, flow: &mut Flow) {}

    /// Called when a flow terminates.
    ///
    /// This is where the columns, defined in the
    /// [`print_header`](trait.T2Plugin.html#method.print_header) method, are filled.
    ///
    /// # Example
    ///
    /// ```
    /// impl T2Plugin for ExamplePlugin {
    ///     ...
    ///     fn on_flow_terminate(&mut self, flow: &mut Flow) {
    ///         // fill the source IPv4 column (bt_ip4_addr)
    ///         match flow.src_ip4() {
    ///             Some(ip) => output_bytes(&ip.octets()),
    ///             None => output_bytes(&[0u8; 4]),
    ///         }
    ///         // fill the HTTP cookies column (repetitive bt_string)
    ///         output_strings(&self.cookies);
    ///     }
    /// }
    /// ```
    #[allow(unused_variables)]
    fn on_flow_terminate(&mut self, flow: &mut Flow) {}

    /// Called before Tranalyzer2 terminates.
    ///
    /// Plugin variables and files should be closed/cleaned here. This method should generally
    /// clean what was created in the [`initialize`](trait.T2Plugin.html#method.initialize)
    /// method.
    fn on_application_terminate() {}
}

/// This structure represents the output header of this plugin.
///
/// A header is defined as a set of columns. Each column is defined by its short name, long name
/// and a definition of the type of data it contains.
pub struct Header {
    main_bv: *mut BinaryValue,
}

impl Header {
    /// Creates a new empty header without any column.
    pub fn new() -> Header {
        Header {
            main_bv: 0 as *mut BinaryValue, // NULL pointer
        }
    }

    /// Returns Tranalyzer2 internal buffer representing the built header.
    ///
    /// This method does not need to be manually called when the [`t2plugin`](macro.t2plugin.html)
    /// macro is used.
    pub fn _internal(&self) -> *mut BinaryValue {
        self.main_bv
    }

    /// Adds a simple column (without compound values) to the header.
    ///
    /// # Example
    ///
    /// ```
    /// impl T2Plugin for ExamplePlugin {
    ///     ...
    ///     fn print_header() -> Header {
    ///         let mut header = Header::new();
    ///         header.add_simple_col("IPv4 source address", "srcIP4", false,
    ///                 BinaryType::bt_ip4_addr);
    ///         header.add_simple_col("HTTP cookies", "httpCookies", true,
    ///                 BinaryType::bt_string);
    ///         header
    ///     }
    /// }
    /// ```
    pub fn add_simple_col(&mut self, long_name: &str, short_name: &str, repeating: bool, bin_type: BinaryType) {
        let long = CString::new(long_name).unwrap().into_raw();
        let short = CString::new(short_name).unwrap().into_raw();
        unsafe {
            self.main_bv = bv_append_bv(self.main_bv, bv_new_bv(long, short, repeating as u32, 1, bin_type as u32));
        }
    }

    /// Adds a compound column to the header.
    ///
    /// # Example
    ///
    /// ```
    /// impl T2Plugin for ExamplePlugin {
    ///     ...
    ///     fn print_header() -> Header {
    ///         let mut header = Header::new();
    ///         // column which contains for each cookie a compound: count_key_value
    ///         header.add_compound_col("HTTP cookies", "httpCookies", true,
    ///                 &[BinaryType::bt_uint_16, BinaryType::bt_string, BinaryType::bt_string]);
    ///         header
    ///     }
    /// }
    /// ```
    pub fn add_compound_col(&mut self, long_name: &str, short_name: &str, repeating: bool, bin_types: &[BinaryType]) {
        let long = CString::new(long_name).unwrap().into_raw();
        let short = CString::new(short_name).unwrap().into_raw();

        // ugly "solution" to expand a slice to a variadic C function
        let t: Vec<u32> = bin_types.into_iter().map(|x| *x as u32).collect();
        unsafe {
            match bin_types.len() {
                0 => return,
                1 => self.main_bv = bv_append_bv(self.main_bv, bv_new_bv(long, short, repeating as u32,
                        1, t[0])),
                2 => self.main_bv = bv_append_bv(self.main_bv, bv_new_bv(long, short, repeating as u32,
                        2, t[0], t[1])),
                3 => self.main_bv = bv_append_bv(self.main_bv, bv_new_bv(long, short, repeating as u32,
                        3, t[0], t[1], t[2])),
                4 => self.main_bv = bv_append_bv(self.main_bv, bv_new_bv(long, short, repeating as u32,
                        4, t[0], t[1], t[2], t[3])),
                5 => self.main_bv = bv_append_bv(self.main_bv, bv_new_bv(long, short, repeating as u32,
                        5, t[0], t[1], t[2], t[3], t[4])),
                6 => self.main_bv = bv_append_bv(self.main_bv, bv_new_bv(long, short, repeating as u32,
                        6, t[0], t[1], t[2], t[3], t[4], t[5])),
                7 => self.main_bv = bv_append_bv(self.main_bv, bv_new_bv(long, short, repeating as u32,
                        7, t[0], t[1], t[2], t[3], t[4], t[5], t[6])),
                8 => self.main_bv = bv_append_bv(self.main_bv, bv_new_bv(long, short, repeating as u32,
                        8, t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7])),
                _ => panic!("add_compound_col: compounds with 9 or more sub-values not implemented."),
            }
        }
    }
}

/// This macro transforms a `struct` implementing the [`T2Plugin`](trait.T2Plugin.html) trait into a
/// plugin which can be loaded by Tranalyzer2.
///
/// This macro creates the necessary `C` interface so the plugin can be loaded by Tranalyzer2. It
/// redirects these `C` functions to their corresponding Rust methods defined when implementing the
/// [`T2Plugin`](trait.T2Plugin.html) trait.
///
/// # Example
///
/// ```
/// struct ExamplePlugin {
///     ...
/// }
///
/// impl T2Plugin for ExamplePlugin {
///     ...
/// }
///
/// // creates the necessary C interface so ExamplePlugin can be loaded in Tranalyzer2
/// t2plugin!(ExamplePlugin);
/// ```
#[macro_export]
macro_rules! t2plugin {
    ($TYPE:ident) => {
        lazy_static! {
            static ref FLOWS: std::sync::Mutex<std::collections::HashMap<t2plugin::c_ulong, $TYPE>> = 
                std::sync::Mutex::new(std::collections::HashMap::new());
        }

        #[no_mangle]
        pub extern "C" fn get_dependencies() -> *const libc::c_char {
            let plugins = $TYPE::get_dependencies().join(",");
            std::ffi::CString::new(plugins).unwrap().into_raw()
        }

        #[no_mangle]
        pub extern "C" fn initialize() {
            // allocate memory for flow structures
            FLOWS.lock().unwrap().reserve(t2plugin::hashchaintable_size());
            // call plugin initialize function
            $TYPE::initialize();
        }

        #[no_mangle]
        pub extern "C" fn get_plugin_name() -> *const libc::c_char {
            std::ffi::CString::new(env!("CARGO_PKG_NAME")).unwrap().into_raw()
        }

        #[no_mangle]
        pub extern "C" fn get_plugin_version() -> *const libc::c_char {
            std::ffi::CString::new(env!("CARGO_PKG_VERSION")).unwrap().into_raw()
        }

        #[no_mangle]
        pub extern "C" fn get_supported_tranalyzer_version_major() -> libc::c_int {
            //env!("CARGO_PKG_VERSION_MAJOR").parse::<libc::c_int>().unwrap()
            env!("CARGO_PKG_VERSION_MAJOR").parse::<libc::c_int>().unwrap()
        }

        #[no_mangle]
        pub extern "C" fn get_supported_tranalyzer_version_minor() -> libc::c_int {
            env!("CARGO_PKG_VERSION_MINOR").parse::<libc::c_int>().unwrap()
        }

        #[no_mangle]
        #[allow(non_snake_case)]
        pub extern "C" fn printHeader() -> *const t2plugin::BinaryValue {
            let header = $TYPE::print_header();
            header._internal()
        }

        #[no_mangle]
        #[allow(non_snake_case)]
        pub extern "C" fn onFlowGenerated(packet: *const Packet, flow_index: t2plugin::c_ulong) {
            let mut flow = $TYPE::new();
            unsafe {
                flow.on_flow_generated(&*packet, t2plugin::getflow(flow_index));
            }
            FLOWS.lock().unwrap().insert(flow_index, flow);
        }

        #[no_mangle]
        #[allow(non_snake_case)]
        pub extern "C" fn claimLayer2Information(packet: *const Packet, flow_index: t2plugin::c_ulong) {
            if flow_index == t2plugin::HASHTABLE_ENTRY_NOT_FOUND {
                unsafe {
                    $TYPE::claim_l2_info(&*packet, None, None);
                }
            } else if flow_index >= t2plugin::hashchaintable_size() as t2plugin::c_ulong {
                println!("ERROR: claimLayer2Information called with flowIndex={}", flow_index);
            } else {
                let mut hashmap = FLOWS.lock().unwrap();
                let plugin = hashmap.entry(flow_index).or_insert($TYPE::new());
                unsafe {
                    $TYPE::claim_l2_info(&*packet, Some(plugin), Some(t2plugin::getflow(flow_index)));
                }
            }
        }

        #[no_mangle]
        #[allow(non_snake_case)]
        pub extern "C" fn claimLayer3Information(packet: *const Packet) {
            unsafe {
                $TYPE::claim_l3_info(&*packet);
            }
        }

        #[no_mangle]
        #[allow(non_snake_case)]
        pub extern "C" fn claimLayer4Information(packet: *const Packet, flow_index: t2plugin::c_ulong) {
            if flow_index >= t2plugin::hashchaintable_size() as t2plugin::c_ulong {
                println!("ERROR: claimLayer4Information called with flowIndex={}", flow_index);
                return;
            }
            let mut hashmap = FLOWS.lock().unwrap();
            let flow = hashmap.entry(flow_index).or_insert($TYPE::new());
            unsafe {
                flow.claim_l4_info(&*packet, t2plugin::getflow(flow_index));
            }
        }

        #[no_mangle]
        #[allow(non_snake_case)]
        pub extern "C" fn onFlowTerminate(flow_index: t2plugin::c_ulong) {
            if flow_index >= t2plugin::hashchaintable_size() as t2plugin::c_ulong {
                println!("ERROR: onFlowTerminate called with flowIndex={}", flow_index);
                return;
            }
            let mut hashmap = FLOWS.lock().unwrap();
            {
                let flow = hashmap.entry(flow_index).or_insert($TYPE::new());
                flow.on_flow_terminate(t2plugin::getflow(flow_index));
            }
            hashmap.remove(&flow_index);
        }

        #[no_mangle]
        #[allow(non_snake_case)]
        pub extern "C" fn onApplicationTerminate() {
            $TYPE::on_application_terminate();
        }
    };
}


#[repr(C)]
struct HashTable {
    hashtable_size: c_ulong,
    hashchaintable_size: c_ulong,
    // we do not need the other fields of the hashtable
}
