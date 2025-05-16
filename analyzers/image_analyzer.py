import io
import re
import math
from core.state import State
from analyzers.base import register_analyzer, analyzer_compatibility

# Optional dependencies
try:
    from PIL import Image, ExifTags
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import cv2
    import numpy as np
    HAS_OPENCV = True
except ImportError:
    HAS_OPENCV = False


def analyze_png_header(state: State) -> None:
    """
    Stub for PNG header analysis when PIL is unavailable.
    """
    state.add_insight(
        "Skipping detailed PNG header analysis (no PIL)",
        analyzer="image_analyzer"
    )


def analyze_jpeg_header(state: State) -> None:
    """
    Stub for JPEG header analysis when PIL is unavailable.
    """
    state.add_insight(
        "Skipping detailed JPEG header analysis (no PIL)",
        analyzer="image_analyzer"
    )


def analyze_gif_header(state: State) -> None:
    """
    Stub for GIF header analysis when PIL is unavailable.
    """
    state.add_insight(
        "Skipping detailed GIF header analysis (no PIL)",
        analyzer="image_analyzer"
    )


def analyze_bmp_header(state: State) -> None:
    """
    Stub for BMP header analysis when PIL is unavailable.
    """
    state.add_insight(
        "Skipping detailed BMP header analysis (no PIL)",
        analyzer="image_analyzer"
    )


@register_analyzer("steganography_analyzer")
@register_analyzer("steganography_extractor")
@register_analyzer("image_analyzer")
@analyzer_compatibility(requires_binary=True)
def analyze_image(state: State, **kwargs) -> State:
    """
    Analyze image for steganography, metadata, and hidden information.
    """
    if not state.binary_data:
        return state

    # Detect type via header
    header = state.binary_data[:8]
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        state.file_type = "png"
    elif header.startswith(b"\xff\xd8"):
        state.file_type = "jpeg"
    elif header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
        state.file_type = "gif"
    elif header.startswith(b"BM"):
        state.file_type = "bmp"
    else:
        state.add_insight("Unsupported or non-image file", analyzer="image_analyzer")
        return state

    state.add_insight(f"Analyzing {state.file_type.upper()} image ({state.file_size} bytes)", analyzer="image_analyzer")

    # PIL-based analysis
    if HAS_PIL:
        analyze_with_pil(state)
    else:
        state.add_insight("PIL not available; limited analysis", analyzer="image_analyzer")
        analyze_without_pil(state)

    # Text extraction from raw bytes
    extract_text_from_image(state)

    # LSB steganography checks
    check_lsb_steganography(state)

    # Embedded-file sniffing
    check_embedded_files(state)

    return state


def analyze_with_pil(state: State) -> None:
    """
    Analyze image using PIL: dimensions, mode, format, color stats, metadata.
    """
    try:
        img = Image.open(io.BytesIO(state.binary_data))
        width, height = img.size
        mode = img.mode
        fmt = img.format
        state.add_insight(f"Image dimensions: {width}×{height}, Mode: {mode}, Format: {fmt}", analyzer="image_analyzer")

        # Color and pattern checks
        if mode in ("RGB", "RGBA"):
            analyze_rgb_image(state, img)
        elif mode == "L":
            analyze_grayscale_image(state, img)
        elif mode == "P":
            analyze_palette_image(state, img)

        # Metadata
        analyze_image_metadata(state, img)

    except Exception as e:
        state.add_insight(f"PIL analysis failed: {e}", analyzer="image_analyzer")


def analyze_without_pil(state: State) -> None:
    """
    Basic header-based analysis without PIL.
    """
    ft = state.file_type
    if ft == "png":
        analyze_png_header(state)
    elif ft in ("jpg", "jpeg"):
        analyze_jpeg_header(state)
    elif ft == "gif":
        analyze_gif_header(state)
    elif ft == "bmp":
        analyze_bmp_header(state)


def analyze_rgb_image(state: State, image) -> None:
    pixels = list(image.getdata())
    total = len(pixels)
    if total == 0:
        return

    unique = len(set(pixels))
    state.add_insight(f"{unique} unique colors out of {total} pixels", analyzer="image_analyzer")
    if unique < 10 and total > 1000:
        state.add_insight("Very few unique colors; possible hidden info", analyzer="image_analyzer")

    # Heuristic LSB suspicion
    if unique < 16:
        state.add_insight("Low color diversity suggests LSB stego", analyzer="image_analyzer")


def analyze_grayscale_image(state: State, image) -> None:
    vals = list(image.getdata())
    total = len(vals)
    if total == 0:
        return

    unique = len(set(vals))
    state.add_insight(f"{unique} gray levels out of {total} pixels", analyzer="image_analyzer")
    if unique < 5 and total > 1000:
        state.add_insight("Low gray diversity; possible hidden info", analyzer="image_analyzer")


def analyze_palette_image(state: State, image) -> None:
    if not getattr(image, "palette", None):
        return
    palette = image.palette.palette or b""
    size = len(palette) // 3
    state.add_insight(f"Palette size: {size} colors", analyzer="image_analyzer")

    used = set(image.getdata())
    if len(used) < size:
        state.add_insight(f"Used {len(used)} of {size} palette entries; unused may hide data",
                          analyzer="image_analyzer")


def analyze_image_metadata(state: State, image) -> None:
    # EXIF
    if hasattr(image, "_getexif") and image._getexif():
        raw = image._getexif()
        exif = {ExifTags.TAGS.get(k, k): v for k, v in raw.items()}
        keep = []
        for tag in ("Artist", "Copyright", "UserComment", "ImageDescription"):
            if tag in exif:
                keep.append(f"{tag}: {exif[tag]}")
        if keep:
            summary = "\n".join(keep)
            state.add_transformation(
                name="EXIF Metadata",
                description="Selected EXIF fields",
                input_data=state.file_type,
                output_data=summary,
                analyzer="image_analyzer"
            )

    # PNG text chunks
    if image.format == "PNG" and hasattr(image, "text") and image.text:
        lines = [f"{k}: {v}" for k, v in image.text.items()]
        body = "\n".join(lines)
        state.add_transformation(
            name="PNG Text Chunks",
            description="Metadata text in PNG",
            input_data="PNG",
            output_data=body,
            analyzer="image_analyzer"
        )
        state.set_puzzle_text(body)


def extract_text_from_image(state: State) -> None:
    data = state.binary_data
    skip = {"png":24, "jpeg":2, "gif":13, "bmp":54}.get(state.file_type, 0)
    if len(data) > skip:
        data = data[skip:]

    strings = find_strings(data, min_length=5)
    if not strings:
        return

    state.add_insight(f"Found {len(strings)} raw text strings", analyzer="image_analyzer")
    filtered = [s for s, _ in strings if not re.search(r"(adobe|jpeg|png|exif|http)", s, flags=re.I)]
    if filtered:
        sample = filtered if len(filtered)<=20 else filtered[:20]+[f"[...and {len(filtered)-20} more...]"]
        text = "\n".join(sample)
        state.add_transformation(
            name="Image Text Extraction",
            description="ASCII/UTF-8 strings",
            input_data=f"bytes[{len(data)}]",
            output_data=text,
            analyzer="image_analyzer"
        )


def check_lsb_steganography(state: State, technique: str = "all", **kwargs) -> None:
    if not HAS_PIL:
        return
    img = Image.open(io.BytesIO(state.binary_data))
    mode = img.mode
    if mode not in ("RGB","RGBA","L","LA"):
        state.add_insight(f"Mode {mode} not optimal for LSB", analyzer="image_analyzer")
        return
    width, height = img.size
    total = width*height
    regions = []
    if total>10000:
        state.add_insight(f"Large image ({width}×{height}); targeted LSB", analyzer="image_analyzer")
        regs=[(0,0,width//10,height//10),(width*9//10,0,width,height//10),
              (0,height*9//10,width//10,height),(width*9//10,height*9//10,width,height),
              (width//3,height//3,width*2//3,height*2//3)]
        regions=regs
    techs = ["rgb","channel","plane"] if technique=="all" else [technique]
    for tech in techs:
        if tech=="rgb" and mode in ("RGB","RGBA"):
            d=extract_lsb_rgb(img,total); analyze_lsb_data(state,d,"RGB combined")
            for i,reg in enumerate(regions):
                d=extract_lsb_rgb_region(img,reg); analyze_lsb_data(state,d,f"Region {i+1}")
        if tech=="channel" and mode in ("RGB","RGBA"):
            for idx,name in enumerate(("Red","Green","Blue")):
                d=extract_lsb_channel(img,idx,total); analyze_lsb_data(state,d,name)
        if tech=="plane" and mode in ("RGB","RGBA","L","LA"):
            for b in range(8):
                d=extract_bit_plane(img,b,total)
                if has_binary_pattern(d):
                    state.add_insight(f"Pattern in bit plane {b}",analyzer="image_analyzer")
                    analyze_lsb_data(state,d,f"Plane {b}")


def check_embedded_files(state: State) -> None:
    data=state.binary_data
    sigs={b"PK\x03\x04":"ZIP",b"Rar!\x1A\x07":"RAR",b"\x1F\x8B\x08":"GZIP",
          b"%PDF":"PDF",b"\x89PNG":"PNG",b"GIF":"GIF",b"ID3":"MP3",b"\x00\x00\x00\x18ftyp":"MP4"}
    found=[]
    for sig,fmt in sigs.items():
        pos=data.find(sig)
        if pos>0: found.append((pos,fmt))
    if not found: return
    state.add_insight(f"Embedded files at: {','.join(str(p) for p,_ in found)}",analyzer="image_analyzer")
    pos,fmt=found[0]
    if fmt=="ZIP":
        eocd = data.rfind(b"PK\x05\x06")
        if eocd>0:
            chunk=data[pos:eocd+22]
            state.add_transformation(
                name="Extracted ZIP",
                description="Embedded ZIP segment",
                input_data=f"Offset {pos}",
                output_data=f"{len(chunk)} bytes of ZIP data",
                analyzer="image_analyzer"
            )

# Utility functions

def find_strings(data: bytes, min_length=4) -> list:
    res=[]; cur=""; start=-1
    for i,b in enumerate(data):
        if 32<=b<=126:
            if start<0: start=i
            cur+=chr(b)
        else:
            if start>=0 and len(cur)>=min_length: res.append((cur,start))
            cur=""; start=-1
    if start>=0 and len(cur)>=min_length: res.append((cur,start))
    return res


def extract_lsb_rgb(image, sample_size):
    w,h=image.size; out=""
    for i in range(min(sample_size,w*h)):
        x=i%w; y=i//w; px=image.getpixel((x,y))
        for c in (0,1,2):
            if c<len(px): out+=str(px[c]&1)
    return out


def extract_lsb_rgb_region(image, region):
    l,t,r,b=region; out=""
    for y in range(t,b):
        for x in range(l,r):
            px=image.getpixel((x,y))
            for c in (0,1,2):
                if c<len(px): out+=str(px[c]&1)
    return out


def extract_lsb_channel(image, idx, sample_size):
    w,h=image.size; out=""
    for i in range(min(sample_size,w*h)):
        x=i%w; y=i//w; px=image.getpixel((x,y))
        if idx<len(px): out+=str(px[idx]&1)
    return out


def extract_bit_plane(image, bit, sample_size):
    w,h=image.size; out=""
    for i in range(min(sample_size,w*h)):
        x=i%w; y=i//w; px=image.getpixel((x,y))
        if isinstance(px,int): out+=str((px>>bit)&1)
        else:
            for c in range(min(3,len(px))): out+=str((px[c]>>bit)&1)
    return out


def analyze_lsb_data(state: State, data: str, src: str):
    if len(data)<32: return
    if has_binary_pattern(data):
        state.add_insight(f"Pattern in {src} LSBs",analyzer="image_analyzer")
        try:
            byts=[int(data[i:i+8],2) for i in range(0,len(data),8) if i+8<=len(data)]
            text="".join(chr(b) if 32<=b<=126 else '.' for b in byts)
            if any(w in text.lower() for w in ("the","and","ctf","flag")):
                state.add_transformation(
                    name=f"LSB→Text ({src})",
                    description="ASCII from LSB bits",
                    input_data=f"{len(data)} bits",
                    output_data=text,
                    analyzer="image_analyzer"
                )
        except:
            pass


def has_binary_pattern(bstr: str) -> bool:
    z=bstr.count("0"); o=bstr.count("1")
    if z==0 or o==0: return False
    if z/o>3 or o/z>3: return False
    groups=[bstr[i:i+8] for i in range(0,len(bstr),8) if i+8<=len(bstr)]
    vals=[int(g,2) for g in groups]
    return len(set(vals))<len(vals)/3 or any(vals.count(v)>3 for v in set(vals))
