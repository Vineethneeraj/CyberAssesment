from flask import Flask, request, jsonify, render_template, redirect
from flask_pymongo import PyMongo


app = Flask(__name__)
 
app.config['MONGO_URI'] = "mongodb+srv://vineethkedasu8:Vinnu22k@datacluster.8ik3p.mongodb.net/threatDB?retryWrites=true&w=majority&appName=DataCluster"

mongo = PyMongo(app)

# Collection
threats_collection = mongo.db.threats

# Home page (dashboard)
@app.route('/')
def index():
    return render_template('index.html')  

# Form page to add a new threat
@app.route("/add_new")
def add_new():
    return render_template("threat_form.html")  

# Add threat to MongoDB
@app.route("/api/add-threat", methods=['POST'])
def add_threat():
    data = request.get_json() 
    if not data:
        return jsonify({"error": "No data received"}), 400

    # Insert into MongoDB
    threats_collection.insert_one({
        "ip": data.get("ip"),
        "domain": data.get("domain"),
        "url": data.get("url"),
        "file_hash": data.get("file_hash"),
        "threat_level": data.get("threat_level")
    })

    return jsonify({"message": "Threat added successfully"}), 201

# Search endpoint
@app.route('/api/threats', methods=['GET'])
def search():
    query = request.args.get('q', '')
    if query:
        results = threats_collection.find({
            "$or": [
                {"ip": {"$regex": query, "$options": "i"}},
                {"domain": {"$regex": query, "$options": "i"}},
                {"threat_level": {"$regex": query, "$options": "i"}}
            ]
        })
    else:
        results = threats_collection.find()

    response = []
    for item in results:
        response.append({
            "ip": item.get("ip", ""),
            "domain": item.get("domain", ""),
            "url": item.get("url", ""),
            "file_hash": item.get("file_hash", ""),
            "threat_level": item.get("threat_level", "")
        })

    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True)
