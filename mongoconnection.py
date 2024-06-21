from pymongo import MongoClient

def get_db():
    client = MongoClient("mongodb+srv://vikas05:VikasKushwaha123@cluster0.w4oeelf.mongodb.net/troven?retryWrites=true&w=majority")
    db = client["expensetracker"]
    return db

def get_expenses_collection():
    db = get_db()
    return db["expenses"]