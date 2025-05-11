def write_file(file_name, content):
    with open(file_name, "w", encoding="UTF-8") as file:
        return file.write(content)