from flask import Blueprint,jsonify

hproblems=Blueprint('hproblems',__name__)

@hproblems.route('/hproblems')
def gethproblems():
    return jsonify({"hola":"si"})

