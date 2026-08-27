#![no_std]
use zero_abi::{gpu::Gpu3dResourceDesc, syscall::SysError};

const PIPE_TEXTURE_2D: u32 = 2;
const VIRGL_FORMAT_B8G8R8X8_UNORM: u32 = 2;
const VIRGL_BIND_RENDER_TARGET: u32 = 1 << 1;
const VIRGL_BIND_DISPLAY_TARGET: u32 = 1 << 7;
const VIRGL_BIND_SCANOUT: u32 = 1 << 18;
const VIRGL_RESOURCE_Y_0_TOP: u32 = 1;
const VIRGL_OBJECT_SURFACE: u32 = 8;
const VIRGL_CCMD_CREATE_OBJECT: u32 = 1;
const VIRGL_CCMD_SET_FRAMEBUFFER_STATE: u32 = 5;
const VIRGL_CCMD_CLEAR: u32 = 7;
const PIPE_CLEAR_COLOR0: u32 = 1 << 2;

const fn cmd0(cmd: u32, obj: u32, len: u32) -> u32 {
    cmd | (obj << 8) | (len << 16)
}
fn print(s: &str) {
    let _ = userlib::console_write(s.as_bytes());
}
fn cleanup(ctx: u32, res: u32) {
    if res != 0 {
        let _ = userlib::gpu3d_resource_destroy(res);
    }
    if ctx != 0 {
        let _ = userlib::gpu3d_context_destroy(ctx);
    }
}
fn fail(code: i32, msg: &str, ctx: u32, res: u32) -> ! {
    print("gputest: FAIL ");
    print(msg);
    print("\r\n");
    cleanup(ctx, res);
    userlib::exit(code)
}

pub extern "C" fn server_main() -> ! {
    print("gputest: probing VirtIO GPU 3D\r\n");
    let info = match userlib::gpu3d_info() {
        Ok(v) => v,
        Err(SysError::NotSupported) | Err(SysError::NotFound) => {
            print("gputest: HOST 3D UNSUPPORTED\r\n");
            userlib::exit(77)
        }
        Err(_) => fail(120, "info", 0, 0),
    };
    if info.flags & zero_abi::gpu::GPU3D_FLAG_VIRGL == 0
        || info.capset_id == 0
        || info.capset_size == 0
    {
        fail(121, "bad info", 0, 0)
    }
    let mut capset = [0u8; 8192];
    if info.capset_size as usize > capset.len() {
        fail(122, "capset too large", 0, 0)
    }
    match userlib::gpu3d_get_capset(
        info.capset_id,
        info.capset_version,
        &mut capset[..info.capset_size as usize],
    ) {
        Ok(n) if n > 0 => print("gputest: CAPSET PASS\r\n"),
        _ => fail(123, "capset", 0, 0),
    }
    let ctx = match userlib::gpu3d_context_create(info.capset_id) {
        Ok(v) => v,
        Err(_) => fail(124, "ctx create", 0, 0),
    };
    let desc = Gpu3dResourceDesc {
        target: PIPE_TEXTURE_2D,
        format: VIRGL_FORMAT_B8G8R8X8_UNORM,
        bind: VIRGL_BIND_RENDER_TARGET | VIRGL_BIND_DISPLAY_TARGET | VIRGL_BIND_SCANOUT,
        width: 64,
        height: 64,
        depth: 1,
        array_size: 1,
        last_level: 0,
        nr_samples: 0,
        flags: VIRGL_RESOURCE_Y_0_TOP,
        backing_bytes: (64 * 64 * 4) as u64,
    };
    let res = match userlib::gpu3d_resource_create(&desc) {
        Ok(v) => v,
        Err(_) => fail(125, "resource create", ctx, 0),
    };
    if userlib::gpu3d_context_attach(ctx, res).is_err() {
        fail(126, "ctx attach", ctx, res)
    }

    // VirGL stream: create surface(resource) -> bind as framebuffer -> clear color0 red.
    // Command header is: low8=cmd, next8=object type, high16=payload dword count.
    let stream: [u32; 19] = [
        cmd0(VIRGL_CCMD_CREATE_OBJECT, VIRGL_OBJECT_SURFACE, 5),
        1,
        res,
        VIRGL_FORMAT_B8G8R8X8_UNORM,
        0,
        0,
        cmd0(VIRGL_CCMD_SET_FRAMEBUFFER_STATE, 0, 3),
        1,
        0,
        1,
        cmd0(VIRGL_CCMD_CLEAR, 0, 8),
        PIPE_CLEAR_COLOR0,
        1.0f32.to_bits(),
        0.0f32.to_bits(),
        0.0f32.to_bits(),
        1.0f32.to_bits(),
        0x0000_0000,
        0x3ff0_0000,
        0,
    ];
    let bytes = unsafe {
        core::slice::from_raw_parts(
            stream.as_ptr().cast::<u8>(),
            core::mem::size_of_val(&stream),
        )
    };
    if userlib::gpu3d_submit(ctx, bytes).is_err() {
        fail(127, "submit", ctx, res)
    }
    let mut pixels = [0u8; 64 * 64 * 4];
    let n = match userlib::gpu3d_readback(res, &mut pixels) {
        Ok(v) => v,
        Err(_) => fail(128, "readback", ctx, res),
    };
    if n < pixels.len() {
        fail(129, "short readback", ctx, res)
    }
    let p = &pixels[..4];
    // B8G8R8X8 little-endian memory: clearing RGBA=(1,0,0,1) => B,G,R ≈ 0,0,255.
    if p[0] > 8 || p[1] > 8 || p[2] < 240 {
        fail(130, "pixel mismatch", ctx, res)
    }
    print("gputest: VIRGL CLEAR+READBACK PASS\r\n");
    cleanup(ctx, res);
    print("gputest: ALL PASS\r\n");
    userlib::exit(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packet_headers() {
        assert_eq!(
            cmd0(VIRGL_CCMD_CREATE_OBJECT, VIRGL_OBJECT_SURFACE, 5),
            0x0005_0801
        );
        assert_eq!(cmd0(VIRGL_CCMD_CLEAR, 0, 8), 0x0008_0007);
    }
}
