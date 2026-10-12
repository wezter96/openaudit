def walk(rows):
    for row in rows:
        if row:
            for cell in row:
                with open(cell) as f:
                    try:
                        if f.read():
                            return True
                    except OSError:
                        pass
    return False
