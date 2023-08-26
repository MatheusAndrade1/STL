--"C:\Program Files\Wireshark\Wireshark.exe" -X lua_script:STL.lua


-- RTP https://www.rfc-editor.org/rfc/rfc3550

STL = Proto("STL",  "Protocol") 

----------------------Tunnel Packet----------------------
V = ProtoField.uint8("stl.Version", "RTP Version", base.DEC) -- 2 BITS
P = ProtoField.uint8("stl.Padding", "Padding", base.DEC) -- 1 BIT
X = ProtoField.uint8("stl.Extension", "Extension", base.DEC) -- 1 BIT
CC = ProtoField.uint8("stl.CSRC", "CSRC count", base.DEC) -- 4 BITS
M = ProtoField.uint8("stl.Marker", "Marker", base.DEC) -- 1 BIT
PT = ProtoField.uint8("stl.Payload_Type", "Payload Type", base.DEC) -- 7 BITS
Sequence_Number = ProtoField.uint8("stl.Sequence_Number", "Sequence Number", base.DEC) -- 16 BITS
Timestamp = ProtoField.uint8("stl.Timestamp", "Timestamp", base.DEC) -- 32 BITS
Protocol_version = ProtoField.uint8("stl.Protocol_version", "Protocol_version", base.DEC) -- 2 BITS
-------

Redundancy = ProtoField.uint8("stl.Redundancy", "Redundancy", base.DEC) -- 2 BITS
Number_of_channels = ProtoField.uint8("stl.Number_of_channels", "Number_of_channels", base.DEC) -- 2 BITS
Reserved = ProtoField.uint8("stl.Reserved", "Reserved", base.DEC) -- 10 OR 14 BITS

-------
Packet_offset = ProtoField.uint8("stl.Packet_offset", "Packet_offset", base.DEC) -- 2 BITS

----------------------Tunneled Packet----------------------
Tunneled_V = ProtoField.uint8("stl.Tunneled_V", "RTP Version", base.DEC) -- 2 BITS
Tunneled_P = ProtoField.uint8("stl.Tunneled_P", "Padding", base.DEC) -- 1 BIT
Tunneled_X = ProtoField.uint8("stl.Tunneled_Extension", "Extension", base.DEC) -- 1 BIT
Tunneled_CC = ProtoField.uint8("stl.Tunneled_CSRC", "CSRC count", base.DEC) -- 4 BITS
Tunneled_M = ProtoField.uint8("stl.Tunneled_Marker", "Marker", base.DEC) -- 1 BIT
Tunneled_PT = ProtoField.uint8("stl.Tunneled_Payload_Type", "Payload Type", base.DEC) -- 7 BITS
Tunneled_Sequence_Number = ProtoField.uint8("stl.Tunneled_Sequence_Number", "Sequence Number", base.DEC) -- 16 BITS
Tunneled_Timestamp = ProtoField.uint8("stl.Tunneled_Timestamp", "Timestamp", base.DEC) -- 32 BITS
Tunneled_SSRC = ProtoField.uint8("stl.Tunneled_SSRC", "Tunneled_SSRC", base.DEC) -- 32 BITS

------------------------------------------------------------
Payload = ProtoField.bytes("stl.Payload", "Payload", base.SPACE) 

-------------------FEC header ---------------------------------
SNBase_low_bits = ProtoField.uint8("stl.SNBase_low_bits", "SNBase_low_bits", base.DEC)
Length_Recovery = ProtoField.uint8("stl.Length_Recovery", "Length_Recovery", base.DEC)
E = ProtoField.uint8("stl.E", "E", base.DEC)
PT_Recovery = ProtoField.uint8("stl.PT_Recovery", "PT_Recovery", base.DEC)
Mask = ProtoField.uint8("stl.Mask", "Mask", base.DEC)
TS_Recovery = ProtoField.uint8("stl.TS_Recovery", "TS_Recovery", base.DEC)
N = ProtoField.uint8("stl.N", "N", base.DEC)
D = ProtoField.uint8("stl.D", "D", base.DEC)
Type = ProtoField.uint8("stl.Type", "Type", base.DEC)
Index = ProtoField.uint8("stl.Index", "Index", base.DEC)
Offset = ProtoField.uint8("stl.Offset", "Offset", base.DEC)
NA = ProtoField.uint8("stl.NA", "NA", base.DEC)
SNBase_ext_bits = ProtoField.uint8("stl.SNBase_ext_bits", "SNBase_ext_bits", base.DEC)


STL.fields = {V, P, X, CC, M, PT, Sequence_Number, Timestamp, Protocol_version, Redundancy, Number_of_channels, Reserved, Packet_offset, Tunneled_V, Tunneled_P, Tunneled_X, Tunneled_CC, Tunneled_M, Tunneled_PT, Tunneled_Sequence_Number, Tunneled_Timestamp, Tunneled_SSRC, Tunneled_CSRC_List, SNBase_low_bits, Length_Recovery, E, PT_Recovery, Mask, TS_Recovery, N, D, Type, Index, Offset, NA, SNBase_ext_bits, Payload}

-- create the dissection function 
function STL.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = STL.name

    local subtree = tree:add(STL, buffer(), "STL Data")

    ----------------------TUNNEL PACKET--------------------------
    -- to separate the bytes into bits, it converts the buffer to string and then to number
    local str_V_P_X_CC = tonumber(tostring(buffer(0,1)),16)
    local V_P_X_CC = toBits(str_V_P_X_CC, 8)

    -- 2 BITS
    subtree:add(V, V_P_X_CC[1]..V_P_X_CC[2]):append_text("")
    -- 1 BIT
    subtree:add(P, V_P_X_CC[3])
    -- 1 BIT
    subtree:add(X, V_P_X_CC[4])
    -- 4 BITS
    subtree:add(CC, V_P_X_CC[5]..V_P_X_CC[6]..V_P_X_CC[7]..V_P_X_CC[8]):append_text("")

    -- to separate the bytes into bits, it converts the buffer to string and then to number
    local str_M_PT = tonumber(tostring(buffer(1,1)),16)
    local M_PT = toBits(str_M_PT, 8)

    -- 1 BIT
    subtree:add(M, M_PT[1])
    -- 7 BITS
    --subtree:add(PT, M_PT[2]..M_PT[3]..M_PT[4]..M_PT[5]..M_PT[6]..M_PT[7]..M_PT[8]):append_text("")
    local PayloadType = tonumber(tostring(M_PT[2]..M_PT[3]..M_PT[4]..M_PT[5]..M_PT[6]..M_PT[7]..M_PT[8]),2)
    subtree:add(PT, PayloadType)

    -- 16 BITS , 2 BYTES
    local sequenceNumber = tonumber(tostring(buffer(2, 2)), 16)
    subtree:add(Sequence_Number, buffer(2, 2))
    -- 32 BITS , 4 BYTES
    subtree:add(Timestamp, buffer(4, 4))

    -- to separate the bytes into bits, it converts the buffer to string and then to number
    local str_Prot_Redundancy_NumChann_Reserved = tonumber(tostring(buffer(8,2)),16)
    local Prot_Redundancy_NumChann_Reserved = toBits(str_Prot_Redundancy_NumChann_Reserved, 16)

    subtree:add(Protocol_version, Prot_Redundancy_NumChann_Reserved[1]..Prot_Redundancy_NumChann_Reserved[2])
    if PayloadType == 97 then
        -- STLTP
        -- 2 BITS
        subtree:add(Redundancy, Prot_Redundancy_NumChann_Reserved[3]..Prot_Redundancy_NumChann_Reserved[4])
        -- 2 BITS
        subtree:add(Number_of_channels, Prot_Redundancy_NumChann_Reserved[5]..Prot_Redundancy_NumChann_Reserved[6])
        -- 10 BITS
        subtree:add(Redundancy, Prot_Redundancy_NumChann_Reserved[7]..Prot_Redundancy_NumChann_Reserved[8]..Prot_Redundancy_NumChann_Reserved[9]..Prot_Redundancy_NumChann_Reserved[10]..Prot_Redundancy_NumChann_Reserved[11]..Prot_Redundancy_NumChann_Reserved[12]..Prot_Redundancy_NumChann_Reserved[13]..Prot_Redundancy_NumChann_Reserved[14]..Prot_Redundancy_NumChann_Reserved[15]..Prot_Redundancy_NumChann_Reserved[16])
    else
        subtree:add(Reserved, Prot_Redundancy_NumChann_Reserved[3]..Prot_Redundancy_NumChann_Reserved[4]..Prot_Redundancy_NumChann_Reserved[5]..Prot_Redundancy_NumChann_Reserved[6]..Prot_Redundancy_NumChann_Reserved[7]..Prot_Redundancy_NumChann_Reserved[8]..Prot_Redundancy_NumChann_Reserved[9]..Prot_Redundancy_NumChann_Reserved[10]..Prot_Redundancy_NumChann_Reserved[11]..Prot_Redundancy_NumChann_Reserved[12]..Prot_Redundancy_NumChann_Reserved[13]..Prot_Redundancy_NumChann_Reserved[14]..Prot_Redundancy_NumChann_Reserved[15]..Prot_Redundancy_NumChann_Reserved[16])
    end 

    -- 32 BITS , 4 BYTES
    subtree:add(Packet_offset, buffer(10, 2))

    local packetOffset = tonumber(tostring(buffer(10,2)),16)
    
    ----------------------TUNNELED PACKET--------------------------
    local CTPEncapsulationOffSet;
    if M_PT[1] == 1 and (packetOffset + 12 + 25) <= length then
        CTPEncapsulationOffSet = 12 + packetOffset
        CTPEncapsulationOffSet = FEC_header(buffer, subtree, CTPEncapsulationOffSet)
    else
        CTPEncapsulationOffSet = 12 + packetOffset
    end

    length = length - CTPEncapsulationOffSet
    
    SaveToFile(sequenceNumber, M_PT[1], length, CTPEncapsulationOffSet, buffer)
    subtree:add(Payload, buffer(CTPEncapsulationOffSet, length))
end

function SaveToFile(sequenceNumber, marker, length, position, buffer)
    ------------------
    if not exists(".\\STLTPDATA") then
        os.execute("mkdir STLTPDATA")
    end 

    filehandle = io.open("STLTPDATA\\"..sequenceNumber.."_"..marker, "a+")

    for i=0,length - 1,1 
    do
        local value = tostring(buffer(position + i, 1))
        filehandle:write(convertByteToBinary(value))
    end
    
    filehandle:close()
end

-- create the dissection function 
function CTP_Encapsulation(buffer, subtree, startBuffer)    
    ----------------------TUNNELED PACKET--------------------------
    local str = tostring(hex2bin(string.lower(tostring(buffer(startBuffer,12)))))
    local CTP_header = {}
    for i = 1, #str do
        CTP_header[i] = str:sub(i, i)
    end
    -- to separate the bytes into bits, it converts the buffer to string and then to number

    -- 2 BITS
    subtree:add(Tunneled_V, getStringSnippet(CTP_header, 1, 2)):append_text(" Tunneled packet")
    -- 1 BIT
    subtree:add(Tunneled_P, CTP_header[3])
    -- 1 BIT
    subtree:add(Tunneled_X, CTP_header[4])
    -- 4 BITS
    subtree:add(Tunneled_CC, getStringSnippet(CTP_header, 5, 8))

    -- 1 BIT
    subtree:add(Tunneled_M, CTP_header[9])
    -- 7 BITS
    subtree:add(Tunneled_PT, tonumber(getStringSnippet(CTP_header, 10, 16), 2)):append_text("")

    -- 16 BITS , 2 BYTES
    subtree:add(Tunneled_Sequence_Number, tonumber(getStringSnippet(CTP_header, 17, 32), 2))--buffer(startBuffer + 2, 2))
    -- 32 BITS , 4 BYTES
    subtree:add(Tunneled_Timestamp, getStringSnippet(CTP_header, 33, 64))
    -- 32 BITS , 4 BYTES
    subtree:add(Tunneled_SSRC, getStringSnippet(CTP_header, 65, 96))

    return startBuffer + 16
end

function FEC_header(buffer, subtree, startBuffer)    
    local str = tostring(hex2bin(string.lower(tostring(buffer(startBuffer,16)))))
    local FEC = {}
    for i = 1, #str do
        FEC[i] = str:sub(i, i)
    end

    local tmpLabel
    subtree:add(SNBase_low_bits, tonumber(getStringSnippet(FEC, 1, 16), 2))
    subtree:add(Length_Recovery, tonumber(getStringSnippet(FEC, 17, 32), 2))
    subtree:add(E, FEC[33])
    subtree:add(PT_Recovery, tonumber(getStringSnippet(FEC, 34, 40), 2))
    subtree:add(Mask, tonumber(getStringSnippet(FEC, 41, 64), 2))
    --print(os.date("%Y-%m-%d %H:%M:%S", tonumber(getStringSnippet(FEC, 65, 96), 2)))
    subtree:add(TS_Recovery, tonumber(getStringSnippet(FEC, 65, 96), 2))
    subtree:add(N, FEC[97])
    subtree:add(D, FEC[98])
    subtree:add(Type, tonumber(getStringSnippet(FEC, 99, 101), 2))
    subtree:add(Index, tonumber(getStringSnippet(FEC, 102, 104), 2))
    subtree:add(Offset, tonumber(getStringSnippet(FEC, 105, 112), 2))
    subtree:add(NA, tonumber(getStringSnippet(FEC, 113, 120), 2))
    subtree:add(SNBase_ext_bits, tonumber(getStringSnippet(FEC, 121, 128), 2))

    return startBuffer + 16
end

function getStringSnippet(strData, start, endString)
    local strResult = ""
    
    for i = start, endString do 
        strResult = strResult..tostring(strData[i])
    end
    return strResult
end

-- Converts the number to bits (bits is the number of bits)
-- Most significant first
function toBits(num,bits)
    bits = bits or math.max(1, select(2, math.frexp(num)))
    local t = {} -- will contain the bits        
    for b = bits, 1, -1 do
        t[b] = math.fmod(num, 2)
        num = math.floor((num - t[b]) / 2)
    end
    return t
end

--- Check if a file or directory exists in this path
function exists(file)
   local ok, err, code = os.rename(file, file)
   if not ok then
      if code == 13 then
         -- Permission denied, but it exists
         return true
      end
   end
   return ok, err
end

function hex2bin(str)
    local map = {
        ['0'] = '0000',
        ['1'] = '0001',
        ['2'] = '0010',
        ['3'] = '0011',
        ['4'] = '0100',
        ['5'] = '0101',
        ['6'] = '0110',
        ['7'] = '0111',
        ['8'] = '1000',
        ['9'] = '1001',
        ['a'] = '1010',
        ['b'] = '1011',
        ['c'] = '1100',
        ['d'] = '1101',
        ['e'] = '1110',
        ['f'] = '1111'
    }
    return str:gsub('[0-9a-f]', map)
end

function convertByteToBinary(str)
    return hex2bin(string.sub(str,1,1))..hex2bin(string.sub(str,2,2))
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(30000, STL)
udp_port:add(8000, STL)
udp_port:add(49152, STL)
udp_port:add(49153, STL)