def format_binary(binary_str):
    # 将二进制字符串从右到左分割成四位一组
    formatted_str = ''
    count = 0
    for bit in reversed(binary_str):
        if count == 4:
            formatted_str = ' ' + formatted_str
            count = 0
        formatted_str = bit + formatted_str
        count += 1

    return formatted_str

# 示例用法
binary_str = "010111011111001010"
formatted_binary = format_binary(binary_str)
print(formatted_binary)






