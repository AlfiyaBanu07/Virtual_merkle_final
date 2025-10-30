# app.py
from flask import Flask, render_template, request, jsonify
from tree import build_merkle_tree, get_proof, verify_proof
from typing import List

app = Flask(__name__, static_folder="static", template_folder="templates")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/generate', methods=['POST'])
def api_generate():
    payload = request.get_json() or {}
    data: List[str] = payload.get('data', [])
    if not isinstance(data, list):
        return jsonify({"error": "data must be a list of strings"}), 400
    levels = build_merkle_tree(data)
    root = levels[-1][0] if levels and levels[-1] else ""
    return jsonify({"levels": levels, "root": root})

@app.route('/api/proof', methods=['POST'])
def api_proof():
    payload = request.get_json() or {}
    data: List[str] = payload.get('data', [])
    value = payload.get('value', "")
    if value not in data:
        return jsonify({"error": "Value not found in leaves"}), 400
    idx = data.index(value)
    proof, root = get_proof(data, idx)
    return jsonify({"proof": proof, "root": root})

@app.route('/api/verify', methods=['POST'])
def api_verify():
    payload = request.get_json() or {}
    value = payload.get('value', "")
    proof = payload.get('proof', [])
    root = payload.get('root', "")
    ok = verify_proof(value, proof, root)
    return jsonify({"result": ok})

if __name__ == '__main__':
    app.run(debug=True, port=5005)
