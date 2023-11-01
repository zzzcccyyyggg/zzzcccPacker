# 打开二进制文件
file_path = r"flag1.exe"

with open(file_path, "rb") as file:
    file_data = file.read()

# 定义要执行异或操作的范围
start_offset = 0x2E00
end_offset = 0x2e00 + 0xd400

# 对指定范围内的字节执行异或操作
modified_data = bytearray(file_data)
for i in range(start_offset, end_offset):
    modified_data[i] ^= 0x23

# 将修改后的内容写回原始文件
with open(file_path, "wb") as file:
    file.write(modified_data)

print(f"文件 {file_path} 的范围从 {start_offset} 到 {end_offset} 的字节已成功处理并保存。")
