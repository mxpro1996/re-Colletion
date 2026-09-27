import struct
import json
import os

def read_leb128(file_obj):
    result = 0
    shift = 0
    while True:
        byte_data = file_obj.read(1)
        if not byte_data:
            raise EOFError("read EOF more")
        byte_val = byte_data[0]
        
        result += (byte_val & 0x7F) << shift
        shift += 7
        
        if (byte_val & 0x80) == 0:
            break
    return result

def extract_string_pak(file_path):
    if not os.path.exists(file_path):
        print(f"No such File: {file_path}")
        return

    output_data = {
        "__metadata__": {
            "description": "J2ME-IMARPG StringPool",
            "mapping_rule": "these strs under block[N], literally could match script-logic under block[N]",
            "usage": "Find symbol-string under 'string.pak', then using corresponding [scene_id:str_idx] to analyse 'script.pak'"
        },
        "blocks": []
    }

    with open(file_path, 'rb') as f:
        # The primary, blockCntInTotal
        pak_block_cnt = f.read(1)[0]
        print(f"pakBlockCnt: {pak_block_cnt} (Blocks)")
        
        # Record detailed length for per-block
        block_lengths = []
        for _ in range(pak_block_cnt):
            block_lengths.append(read_leb128(f))
            
        """
        calculate 'startAddr' of every block[N] at 'script.pak'
        actually we could find this at encrypted class, like the 'globalPakOffset'
        """
        header_size = f.tell()
        absolute_offsets = [header_size]
        for length in block_lengths:
            absolute_offsets.append(absolute_offsets[-1] + length)

        """
        foreach all blocks, or precisely the "sceneX"
        because in the J2ME era, we like to merge entity as specified scene/map
        Just like the RPG-Maker, when we enter into anyScene, then call that block
        """
        for block_id in range(pak_block_cnt):
            f.seek(absolute_offsets[block_id])
            
            # [short-16bit] as the cntTotal of StringPool
            str_cnt_data = f.read(2)
            if len(str_cnt_data) < 2:
                break
            str_cnt = struct.unpack('>h', str_cnt_data)[0]  # >h RMSer like Big-Littean
            
            # foreach all strs under sceneX
            len_bytes = f.read(str_cnt * 2)
            str_lengths = struct.unpack('>' + 'h' * str_cnt, len_bytes)
            
            # We need the structure to organize sth
            block_data = {
                "block_id": block_id,
                "scene_id": block_id - 1 if block_id > 0 else "GLOBAL_SYSTEM",
                "string_count": str_cnt,
                "block_strings": {}
            }
            
            for string_idx, length in enumerate(str_lengths):
                if length == 0:
                    block_data["block_strings"][string_idx] = ""
                else:
                    str_bytes = f.read(length)
                    try:
                        text = str_bytes.decode('utf-8')
                    except UnicodeDecodeError:
                        text = str_bytes.decode('gbk', errors='replace')
                    
                    # saveWithIDX, for xref check
                    block_data["block_strings"][string_idx] = text
                    
            output_data["blocks"].append(block_data)
            print(f"Extracted Block {block_id:02d} | xrefScene: {block_data['scene_id']} | textSum: {str_cnt} ")

    output_file = "string_unpacked.json"
    with open(output_file, 'w', encoding='utf-8') as out_f:
        json.dump(output_data, out_f, indent=4, ensure_ascii=False)
        
    print(f"\nExtracted Fin！Save to: {output_file}")

if __name__ == "__main__":
    extract_string_pak("string.pak")