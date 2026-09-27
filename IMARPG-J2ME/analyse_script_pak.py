import struct
import os
# Test at IMAPRG21 only



"""
(Opcode: ArgCount)
    Anything has its principle, after endless analysis on JADX, the game's opcode-dispatcher will see this table to get argCount.
    Maybe not useful for newer IMARPG, like version-3.
/* renamed from: d */
public static final int[] scriptPool = {7, 0, 0, 5, 4, 3, 2, 6, 3, 1, 3, 
                                        2, 4, 4, 1, 0, 8, 3, 3, 2, 3, 3, 
                                        0, 0, 2, 2, 4, 4, 1, 3, 6, 5, 2, 
                                        5, 3, 3, 1, 3, 3, 3, 2, 7, 7, 5, 
                                        7, 7, 0, 1, 3, 4, 3, 3, 2, 5, 3, 
                                        2, 1, 3, 2, 2, 5, 1, 5, 4, 1, 2, 
                                        5, 2, 2, 1, 0, 2, 3, 4, 4, 1};
it's obvious that some counts doesn't match, owing to curious region,
or just I don't know how to handle alignment or barrier, so we'd better to think twice.
"""
OPCODE_ARG_COUNTS = {
    0:7,  1:0,  2:0,  3:5,  4:4,  5:3,  6:2,  7:6,  8:3,  9:1,  10:3,
    11:2, 12:4, 13:4, 14:1, 15:0, 16:8, 17:3, 18:3, 19:2, 20:3, 21:3, 
    22:0, 23:0, 24:2, 25:2, 26:4, 27:4, 28:1, 29:3, 30:4, 31:5, 32:2, 
    33:5, 34:3, 35:3, 36:1, 37:3, 38:3, 39:3, 40:2, 41:7, 42:7, 43:5, 
    44:7, 45:6, 46:0, 47:1, 48:3, 49:4, 50:3, 51:3, 52:2, 53:5, 54:3, 
    55:2, 56:1, 57:3, 58:2, 59:2, 60:5, 61:1, 62:5, 63:4, 64:1, 65:2, 
    66:5, 67:2, 68:2, 69:1, 70:0, 71:2, 72:3, 73:4, 74:0, 75:1
}

#  (CORE_OPCODE)
OPCODE_NAMES = {
    0: "IF_JUMP",          1: "END_IF",          2: "TERMINATE",
    3: "VAR_MATH",         4: "CHANGE_SCENE",    5: "SET_ACTOR_POS",
    6: "SET_ACTOR_VISIBLE",7: "SHOW_DIALOG",     8: "SET_ACTOR_DIR",
    9: "WAIT_TIMER",       10: "CAM_LOCK_COORD", 11: "CAM_LOCK_ACTOR",
    12: "SET_ACTOR_FRAME", 13: "ACTOR_MOVE",     14: "WAIT_ACTOR_MOVE",
    15: "GOTO",            16: "SHOW_CHOICE",    17: "SET_ACTOR_PROP",
    18: "SCREEN_EFFECT",   19: "ITEM_MONEY_OP",  20: "RECOVER_HP_MP",
    21: "START_BATTLE",    22: "GAME_OVER",      24: "SHOW_MESSAGE",
    25: "GET_ITEM_COUNT",  26: "SHOP_INIT",      27: "SET_QUEST_FLAG",
    28: "SET_PLAYER_CTRL", 29: "CHANGE_TILE",    30: "SCREEN_SHAKE",
    31: "SET_WEATHER",     32: "SET_ACTOR_SPEED", 33: "ACTOR_PATH_MOVE",
    34: "ACTOR_JUMP",      35: "CHANGE_TILE_VAR", 36: "SET_ALL_ANIM",
    37: "SHOW_EMOTION",    38: "GET_ACTOR_ATTR",  39: "SET_PARTY_STAT",
    40: "SPECIAL_ACTION",  41: "MENU_BUILD_1",    42: "MENU_BUILD_2",
    46: "HIDE_ELEMENT",    47: "SET_BATTLE_BG",   48: "GET_ACTOR_STAT",
    49: "EQUIP_ITEM",      50: "GET_ACTOR_STATE", 51: "SET_ACTOR_STATE",
    52: "PLAY_BGM",        53: "PAN_SCREEN",      54: "ADD_BASE_STAT",
    55: "OPEN_SYS_MENU",   56: "VIBRATE_DEVICE",  57: "GIVE_ITEM_2",
    58: "COPY_VAR",        59: "SET_CLASS",       65: "UNLOCK_PORTRAIT",
    66: "SHOW_OVERLAY",    67: "CHANGE_UI_GFX",   68: "LEARN_SKILL",
    69: "MOUNT_VEHICLE",   70: "SET_MOUNT_POS",   71: "WAIT_INPUT",
    72: "PARTY_JOIN_LEAVE", 73: "SET_SAVE_POINT", 74: "TELEPORT_TO_SAVE",
    75: "SET_ENCOUNTER_RATE"
}

class DataReader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def read_byte(self):
        val = struct.unpack_from(">b", self.data, self.pos)[0]
        self.pos += 1
        return val

    def read_ubyte(self):
        val = struct.unpack_from(">B", self.data, self.pos)[0]
        self.pos += 1
        return val

    def read_short(self):
        val = struct.unpack_from(">h", self.data, self.pos)[0]
        self.pos += 2
        return val

def unpack_pak(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    
    reader = DataReader(data)
    block_cnt = reader.read_ubyte()
    
    sizes = []
    # analyse the LEB128 encode-var
    for _ in range(block_cnt):
        size = 0
        shift = 0
        while True:
            b = reader.read_ubyte()
            size += (b & 0x7F) << shift
            shift += 7
            if not (b & 0x80):
                break
        sizes.append(size)
    
    # split child-files
    sub_files = []
    for size in sizes:
        sub_files.append(data[reader.pos : reader.pos + size])
        reader.pos += size
        
    return sub_files

def parse_script_bin(data, scene_id):
    reader = DataReader(data)
    
    # 1. read the count of blockHead
    packHeadCnt = reader.read_short()
    
    # 2. read four basic arrays
    entity_ids = [reader.read_short() for _ in range(packHeadCnt)]
    trigger_types = [reader.read_byte() for _ in range(packHeadCnt)]
    flags = [reader.read_byte() for _ in range(packHeadCnt)]
    cmd_counts = [reader.read_short() for _ in range(packHeadCnt)]
    
    total_cmds = sum(cmd_counts)
    
    # 3. getAllOpcodes
    opcodes = [reader.read_short() for _ in range(total_cmds)]
    
    # 4. calc&obtain the args as the assumed list
    total_args = sum([OPCODE_ARG_COUNTS.get(op, 0) for op in opcodes])
    arguments = [reader.read_short() for _ in range(total_args)]
    
    # start the assembly of RPG Opcode
    out_lines = []
    out_lines.append(f"=== SCENE {scene_id} ===")
    out_lines.append(f"Total Blocks: {packHeadCnt}, Total Commands: {total_cmds}\n")
    
    global_cmd_idx = 0
    global_arg_idx = 0
    
    for i in range(packHeadCnt):
        out_lines.append(f"[Block {i}] EntityID: {entity_ids[i]}, TriggerType: {trigger_types[i]}, Flag: {flags[i]}, Cmds: {cmd_counts[i]}")
        
        for _ in range(cmd_counts[i]):
            opcode = opcodes[global_cmd_idx]
            arg_cnt = OPCODE_ARG_COUNTS.get(opcode, 0)
            
            # slice get current opcode's args
            args = arguments[global_arg_idx : global_arg_idx + arg_cnt]
            
            op_name = OPCODE_NAMES.get(opcode, f"CMD_{opcode}")
            args_str = ", ".join([str(a) for a in args])
            
            out_lines.append(f"    {op_name}({args_str})")
            
            global_cmd_idx += 1
            global_arg_idx += arg_cnt
            
        out_lines.append("") # 'space' split
        
    return "\n".join(out_lines)

def encode_leb128(val):
    buf = bytearray()
    while True:
        b = val & 0x7F
        val >>= 7
        if val != 0:
            b |= 0x80
            buf.append(b)
        else:
            buf.append(b)
            break
    return buf    
    
def repack_pak(out_dir, target_pak_file):
    bin_files = sorted(
        [f for f in os.listdir(out_dir) if f.startswith("scene_") and f.endswith(".bin")],
        key=lambda x: int(x.split("_")[1].split(".")[0])
    )
    
    if not bin_files:
        print(f"Error: No scene_X.bin found in {out_dir}.")
        return

    buf = bytearray()
    
    # 1. Modify the pakBlockCnt (u8)
    buf.extend(struct.pack(">B", len(bin_files)))
    
    # 2. foreach the LEB128-size && RawData
    sub_files_data = []
    for bf in bin_files:
        with open(os.path.join(out_dir, bf), "rb") as f:
            sub_files_data.append(f.read())
    for data in sub_files_data:
        buf.extend(encode_leb128(len(data)))
    for data in sub_files_data:
        buf.extend(data)
        
    with open(target_pak_file, "wb") as f:
        f.write(buf)
        
    print(f"[✓] Repacked {len(bin_files)} scenes into {target_pak_file}")
 


def main():
    parser = argparse.ArgumentParser(description="IMAPRG21 PAK Unpacker & Repacker Tool")
    parser.add_argument("-i", "--input", default="script.pak", help="Path to input PAK file (default: script.pak)")
    parser.add_argument("-o", "--out-dir", default="script_out", help="Directory for extracted scene files (default: script_out)")
    parser.add_argument("-r", "--repack", metavar="TARGET_PAK", help="Repack mode: Pack binary files from out-dir back into target PAK file")
    
    args = parser.parse_parse_args() if hasattr(parser, 'parse_parse_args') else parser.parse_args()
    # isRepack mode?
    if args.repack:
        print(f"Repacking scripts from '{args.out_dir}' into '{args.repack}'...")
        repack_pak(args.out_dir, args.repack)
        return

    if not os.path.exists(args.input):
        print(f"Error: {args.input} not found.")
        return

    if not os.path.exists(args.out_dir):
        os.makedirs(args.out_dir)

    print(f"Unpacking {args.input}...")
    sub_files = unpack_pak(args.input)
    print(f"Found {len(sub_files)} scripts in {args.input}.")

    for i, data in enumerate(sub_files):
        bin_path = os.path.join(args.out_dir, f"scene_{i}.bin")
        txt_path = os.path.join(args.out_dir, f"scene_{i}.txt")

        # dump the bare-raw as bin
        with open(bin_path, "wb") as f:
            f.write(data)

        # deserialized as text
        try:
            parsed_text = parse_script_bin(data, i)
            with open(txt_path, "w", encoding="utf-8") as f:
                f.write(parsed_text)
            print(f"\r  -> Extracted and parsed Scene {i}", end="", flush=True)
        except Exception as e:
            print(f"  -> [!] Error parsing Scene {i}: {e}")

if __name__ == "__main__":
    main()

