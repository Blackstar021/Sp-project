from app import DATABASE, initialize_database


if __name__ == "__main__":
    initialize_database(DATABASE)
    print(f"CyberSafe database seeded at {DATABASE}")
