from flask import Flask, request, jsonify
from flask_restful import Api, Resource, reqparse
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from datetime import datetime
from routes.heuristicproblemsroutes import hproblems
from models.heuristicowner import HeuristicOwner
from datetime import datetime, timezone, timedelta
#####################################

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask import request, jsonify
from flask_login import login_user, logout_user, login_required, current_user, login_manager
from hashlib import sha256
from flask import redirect, url_for, render_template

app = Flask(__name__)
CORS(app, origins=['http://localhost:5000'])
CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}})
app.register_blueprint(hproblems)
CORS(app)
api = Api(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:1234@localhost/usabilitydb'
db = SQLAlchemy(app)

#///////////////////////////////////////////////////////////////////////
#///////////////////////////////////////////////////////////////////////

def get_colombia_time():
    return datetime.now(timezone.utc) - timedelta(hours=5)

# Modelo para la creacion de la tabla Usuario
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    rol = db.Column(db.String(20), nullable=False)
    experience = db.Column(db.String(10), nullable=False, default='novato')
    password_hash = db.Column(db.String(1024), nullable=False)
    design_owners = db.relationship('DesignOwner', backref = 'owner', lazy = True)
    evaluator_access = db.relationship('EvaluatorAccess', backref='evaluator', lazy=True)
    responses = db.relationship('EvaluatorResponse', backref='evaluator', lazy=True)

    def set_password(self, password):
        self.password_hash = sha256(password.encode('utf-8')).hexdigest()

    def check_password(self, password):
        return self.password_hash == sha256(password.encode('utf-8')).hexdigest()

# Modelo para la creacion de la tabla de Gestion de pruebas de Diseño
class DesignOwner(db.Model):
    test_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    test_type = db.Column(db.Enum('Movil', 'Web', 'Tablet'), nullable=False)
    code = db.Column(db.String(10), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=get_colombia_time)
    design_questionnaires = db.relationship('DesignQuestionnaires', backref='design_owner', lazy=True)
    evaluator_access = db.relationship('EvaluatorAccess', backref='design_owner', lazy=True)

# Modelo para la creacion de la tabla para la creacion de los cuestionarios
class DesignQuestionnaires(db.Model):
    questionnaire_id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(db.Integer, db.ForeignKey('design_owner.test_id'), nullable=False)
    title = db.Column(db.String(250), nullable=False)
    description = db.Column(db.String(250), nullable=False)
    url_frame = db.Column(db.String(500), nullable=False)
    response_type = db.Column(db.Enum('Calificación', 'Legibilidad', 'Coherencia'), nullable=False)
    responses = db.relationship('EvaluatorResponse', backref='design_questionnaire', lazy=True)

# Modelo de la creacion de la tabla para el acceso de los Evaluadores
class EvaluatorAccess(db.Model):
    access_id = db.Column(db.Integer, primary_key=True)
    evaluator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    test_id = db.Column(db.Integer, db.ForeignKey('design_owner.test_id'), nullable=False)
    acceso_bloqueado = db.Column(db.Boolean, default=False)
    accessed_at = db.Column(db.DateTime, nullable=False, default=get_colombia_time)
    is_hidden = db.Column(db.Boolean, default=False)

# Modelo de la creacion de la tabla de las respuestas de los Evaluadores
class EvaluatorResponse(db.Model):
    response_id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(db.Integer, db.ForeignKey('design_owner.test_id'), nullable=False)  # Nuevo campo
    questionnaire_id = db.Column(db.Integer, db.ForeignKey('design_questionnaires.questionnaire_id'), nullable=False)
    evaluator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    response_type = db.Column(db.Enum('Calificación', 'Legibilidad', 'Coherencia'), nullable=False)
    response_value = db.Column(db.Integer, nullable=False)
    respuesta = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=get_colombia_time)

#///////////////////////////////////////////////////////////////////////
#///////////////////////////////////////////////////////////////////////

# clase de modelo nombrada HeuristicOwner
class HeuristicOwner(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    checklists = db.relationship('HeuristicCheckList', backref='owner', lazy=True)

# clase de modelo nombrada HeuristiEvaluations
class HeuristicEvaluations(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('heuristic_owner.id'), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    description = db.Column(db.String(250), nullable=False)
    hi = db.Column(db.String(250), nullable=False)
    incidents = db.Column(db.Integer, nullable=False)
    severity = db.Column(db.Integer, nullable=False)
    frequency = db.Column(db.Integer, nullable=False)
    criticism = db.Column(db.Integer, nullable=False)

# clase de modelo nombrada HeuristicDescription
class HeuristicDescriptions(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(500), nullable=False)

# clase de modelo nombrada HeuristcChecklist
class HeuristicCheckList(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('heuristic_owner.id'), nullable=False)
    H01P01 = db.Column(db.Boolean, nullable=False)
    H01P02 = db.Column(db.Boolean, nullable=False)
    H01P03 = db.Column(db.Boolean, nullable=False)
    H01P04 = db.Column(db.Boolean, nullable=False)
    H01P05 = db.Column(db.Boolean, nullable=False)
    H01P06 = db.Column(db.Boolean, nullable=False)
    H01P07 = db.Column(db.Boolean, nullable=False)

    H02P01 = db.Column(db.Boolean, nullable=False)
    H02P02 = db.Column(db.Boolean, nullable=False)
    H02P03 = db.Column(db.Boolean, nullable=False)
    H02P04 = db.Column(db.Boolean, nullable=False)
    H02P05 = db.Column(db.Boolean, nullable=False)
    H02P06 = db.Column(db.Boolean, nullable=False)
    H02P07 = db.Column(db.Boolean, nullable=False)
    H02P08 = db.Column(db.Boolean, nullable=False)

    H03P01 = db.Column(db.Boolean, nullable=False)
    H03P02 = db.Column(db.Boolean, nullable=False)
    H03P03 = db.Column(db.Boolean, nullable=False)
    H03P04 = db.Column(db.Boolean, nullable=False)
    H03P05 = db.Column(db.Boolean, nullable=False)
    H03P06 = db.Column(db.Boolean, nullable=False)
    H03P06 = db.Column(db.Boolean, nullable=False)
    H04P01 = db.Column(db.Boolean, nullable=False)
    H04P02 = db.Column(db.Boolean, nullable=False)
    H04P03 = db.Column(db.Boolean, nullable=False)
    H04P04 = db.Column(db.Boolean, nullable=False)
    H04P05 = db.Column(db.Boolean, nullable=False)
    H04P06 = db.Column(db.Boolean, nullable=False)
    H04P07 = db.Column(db.Boolean, nullable=False)
    H04P08 = db.Column(db.Boolean, nullable=False)
    H04P09 = db.Column(db.Boolean, nullable=False)
    H04P10 = db.Column(db.Boolean, nullable=False)
    H04P11 = db.Column(db.Boolean, nullable=False)
    H04P12 = db.Column(db.Boolean, nullable=False)
    H04P13 = db.Column(db.Boolean, nullable=False)
    H05P01 = db.Column(db.Boolean, nullable=False)
    H05P02 = db.Column(db.Boolean, nullable=False)
    H05P03 = db.Column(db.Boolean, nullable=False)
    H05P04 = db.Column(db.Boolean, nullable=False)
    H05P05 = db.Column(db.Boolean, nullable=False)
    H06P01 = db.Column(db.Boolean, nullable=False)
    H06P02 = db.Column(db.Boolean, nullable=False)
    H06P03 = db.Column(db.Boolean, nullable=False)
    H07P01 = db.Column(db.Boolean, nullable=False)
    H07P02 = db.Column(db.Boolean, nullable=False)
    H07P03 = db.Column(db.Boolean, nullable=False)
    H07P04 = db.Column(db.Boolean, nullable=False)
    H07P05 = db.Column(db.Boolean, nullable=False)
    H07P06 = db.Column(db.Boolean, nullable=False)
    H07P07 = db.Column(db.Boolean, nullable=False)
    H08P01 = db.Column(db.Boolean, nullable=False)
    H08P02 = db.Column(db.Boolean, nullable=False)
    H08P03 = db.Column(db.Boolean, nullable=False)
    H08P04 = db.Column(db.Boolean, nullable=False)
    H08P05 = db.Column(db.Boolean, nullable=False)
    H08P06 = db.Column(db.Boolean, nullable=False)
    H08P07 = db.Column(db.Boolean, nullable=False)
    H08P08 = db.Column(db.Boolean, nullable=False)
    H08P09 = db.Column(db.Boolean, nullable=False)
    H08P10 = db.Column(db.Boolean, nullable=False)
    H08P11 = db.Column(db.Boolean, nullable=False)
    H09P01 = db.Column(db.Boolean, nullable=False)
    H09P02 = db.Column(db.Boolean, nullable=False)
    H09P03 = db.Column(db.Boolean, nullable=False)
    H09P04 = db.Column(db.Boolean, nullable=False)
    H09P05 = db.Column(db.Boolean, nullable=False)
    H09P06 = db.Column(db.Boolean, nullable=False)
    H10P01 = db.Column(db.Boolean, nullable=False)
    H10P02 = db.Column(db.Boolean, nullable=False)
    H10P03 = db.Column(db.Boolean, nullable=False)
    H10P04 = db.Column(db.Boolean, nullable=False)
    H10P05 = db.Column(db.Boolean, nullable=False)
    H10P06 = db.Column(db.Boolean, nullable=False)
    H10P07 = db.Column(db.Boolean, nullable=False)
    H10P08 = db.Column(db.Boolean, nullable=False)
    H10P09 = db.Column(db.Boolean, nullable=False)
    OBSERVACIONH1 = db.Column(db.String(300), nullable=False)
    OBSERVACIONH2 = db.Column(db.String(300), nullable=False)
    OBSERVACIONH3 = db.Column(db.String(300), nullable=False)
    OBSERVACIONH4 = db.Column(db.String(300), nullable=False)
    OBSERVACIONH5 = db.Column(db.String(300), nullable=False)
    OBSERVACIONH6 = db.Column(db.String(300), nullable=False)
    OBSERVACIONH7 = db.Column(db.String(300), nullable=False)
    OBSERVACIONH8 = db.Column(db.String(300), nullable=False)
    OBSERVACIONH9 = db.Column(db.String(300), nullable=False)
    OBSERVACIONH10 = db.Column(db.String(300), nullable=False)

#///////////////////////////////////////////////////////////////////////
#///////////////////////////////////////////////////////////////////////

#Ruta para verificar si un codigo ya está en uso
@app.route('/designtests/checkcode/<code>', methods=['GET'])
def check_code(code):
    exists = db.session.query(DesignOwner.id).filter_by(code=code).first() is not None
    return jsonify({'exists': exists})

# Ruta para enviar una nueva prueba de diseño
@app.route('/designtests', methods=['POST'])
def create_design_test():
    data = request.json
    
    new_test = DesignOwner(
        user_id=data['user_id'],
        name=data['name'],
        url=data['url'],
        description=data['description'],
        test_type=data['test_type'],
        code=data['code'],
        created_at=get_colombia_time()
    )
    db.session.add(new_test)
    db.session.commit()
    return jsonify({"message": "Prueba de diseño creada exitosamente"}), 201

# Ruta para obtener todas las pruebas de diseño de un owner
@app.route('/designtests/<int:user_id>', methods=['GET'])
def get_design_tests(user_id):
    tests = DesignOwner.query.filter_by(user_id=user_id).all()
    if not tests:
        return jsonify([]), 200
    
    tests_data = [
        {
            'test_id': test.test_id,
            'name': test.name,
            'url': test.url,
            'description': test.description,
            'test_type': test.test_type,
            'code': test.code,
            'created_at': test.created_at
        }
        for test in tests
    ]
    return jsonify(tests_data), 200

# Ruta para eliminar una prueba de diseño
@app.route('/designtests/<int:test_id>', methods=['DELETE'])
def delete_design_test(test_id):
    test = DesignOwner.query.get(test_id)
    
    if not test:
        return jsonify({"message": "Prueba de diseño no encontrada"}), 404
    
    db.session.delete(test)
    db.session.commit()
    return jsonify({"message": "Prueba de diseño eliminada exitosamente"}), 200


#//////////////////////////////////////////////////////////////////
#//////////////////////////////////////////////////////////////////

# Ruta para crear un nuevo cuestionario dentro de una prueba de diseño
@app.route('/designtests/<int:test_id>/questionnaires', methods=['POST'])
def create_questionnaire(test_id):
    data = request.json

    new_questionnaire = DesignQuestionnaires(
        test_id=test_id,
        title=data['title'],
        description=data['description'],
        url_frame=data['url_frame'],
        response_type=data['response_type']
    )
    db.session.add(new_questionnaire)
    db.session.commit()
    return jsonify({"message": "Cuestionario creado exitosamente"}), 201

# Ruta para obtener todos los cuestionarios de una prueba de diseño
@app.route('/designtests/<int:test_id>/questionnaires', methods=['GET'])
def get_questionnaires(test_id):
    questionnaires = DesignQuestionnaires.query.filter_by(test_id=test_id).all()
    if not questionnaires:
        return jsonify({"message": "No se encontraron cuestionarios para esta prueba de diseño"}), 404
    
    questionnaires_data = [
        {
            'questionnaire_id': q.questionnaire_id,
            'title': q.title,
            'description': q.description,
            'url_frame': q.url_frame,
            'response_type': q.response_type
        }
        for q in questionnaires
    ]
    return jsonify(questionnaires_data), 200

# Ruta para editar un cuestionario existente
@app.route('/designtests/<int:test_id>/questionnaires/<int:questionnaire_id>', methods=['PUT'])
def edit_questionnaire(test_id, questionnaire_id):
    data = request.json
    questionnaire = DesignQuestionnaires.query.get(questionnaire_id)
    
    if not questionnaire or questionnaire.test_id != test_id:
        return jsonify({"message": "Cuestionario no encontrado o no autorizado"}), 404
    
    questionnaire.title = data.get('title', questionnaire.title)
    questionnaire.description = data.get('description', questionnaire.description)
    questionnaire.url_frame = data.get('url_frame', questionnaire.url_frame)
    questionnaire.response_type = data.get('response_type', questionnaire.response_type)
    db.session.commit()
    return jsonify({"message": "Cuestionario editado exitosamente"}), 200

# Ruta para eliminar un cuestionario existente
@app.route('/designtests/<int:test_id>/questionnaires/<int:questionnaire_id>', methods=['DELETE'])
def delete_questionnaire(test_id, questionnaire_id):
    questionnaire = DesignQuestionnaires.query.get(questionnaire_id)
    
    if not questionnaire or questionnaire.test_id != test_id:
        return jsonify({"message": "Cuestionario no encontrado o no autorizado"}), 404
    
    db.session.delete(questionnaire)
    db.session.commit()
    return jsonify({"message": "Cuestionario eliminado exitosamente"}), 200

#//////////////////////////////////////////////////////////////////////
#//////////////////////////////////////////////////////////////////////

# Ruta para digitar el codigo y guardar las pruebas de diseño de un evaluador
@app.route('/designtests/access', methods=['POST'])
def access_design_test():
    data = request.json
    code = data.get('code')
    evaluator_id = data.get('evaluator_id')

    if not code or not evaluator_id:
        return jsonify({"message": "Código o ID del evaluador no proporcionado"}), 400

    design_test = DesignOwner.query.filter_by(code=code).first()
    if not design_test:
        return jsonify({"message": "Prueba de diseño no encontrada"}), 404

    existing_access = EvaluatorAccess.query.filter_by(evaluator_id=evaluator_id, test_id=design_test.test_id).first()
    if not existing_access:
        
        new_access = EvaluatorAccess(
            evaluator_id=evaluator_id,
            test_id=design_test.test_id,
            accessed_at=get_colombia_time()
        )
        db.session.add(new_access)
        db.session.commit()

    design_test_data = {
        'test_id': design_test.test_id,
        'name': design_test.name,
        'url': design_test.url,
        'description': design_test.description,
        'test_type': design_test.test_type,
        'created_at': design_test.created_at,
        'code': design_test.code
    }

    return jsonify(design_test_data), 200

# Ruta para obtener las pruebas de diseño por evaluador
@app.route('/designtests/access/<int:evaluator_id>', methods=['GET'])
def get_design_tests_access(evaluator_id):
    access_entries = EvaluatorAccess.query.filter_by(evaluator_id=evaluator_id, is_hidden=False).all()

    if not access_entries:
        return jsonify([]), 200

    tests_data = []

    for access in access_entries:
        test = DesignOwner.query.get(access.test_id)
        if test:
            tests_data.append({
                'test_id': test.test_id,
                'name': test.name,
                'description': test.description,
                'url': test.url,
                'test_type': test.test_type,
                'created_at': access.accessed_at,
                'access_blocked': access.acceso_bloqueado
            })
    return jsonify(tests_data), 200

# Ruta para ocultar la prueba de usuario para el evaluador
@app.route('/designtests/access/<int:test_id>/hide', methods=['POST'])
def hide_design_test_access(test_id):
    data = request.json
    evaluator_id = data.get('evaluator_id')

    access = EvaluatorAccess.query.filter_by(test_id=test_id, evaluator_id=evaluator_id).first()

    if not access:
        return jsonify({"message": "Acceso no encontrado"}), 404

    access.is_hidden = True
    db.session.commit()
    return jsonify({"message": "Acceso ocultado exitosamente"}), 200

#//////////////////////////////////////////////////////////////////////
#//////////////////////////////////////////////////////////////////////

# Ruta para guardar la respuesta de un cuestionario
@app.route('/questionnaires/<int:questionnaire_id>/responses', methods=['POST'])
def save_questionnaire_response(questionnaire_id):
    data = request.json

    existing_response = EvaluatorResponse.query.filter_by(questionnaire_id=questionnaire_id, evaluator_id=data['evaluator_id']).first()
    
    if existing_response:
        existing_response.response_value = data.get('response_value', existing_response.response_value)
        existing_response.respuesta = data.get('respuesta', existing_response.respuesta)
        existing_response.created_at = get_colombia_time()
    else:
        new_response = EvaluatorResponse(
            test_id=data['test_id'],
            questionnaire_id=questionnaire_id,
            evaluator_id=data['evaluator_id'],
            response_value=data['response_value'],
            respuesta=data['respuesta'],
            created_at=get_colombia_time(),
            response_type=data['response_type']
        )
        db.session.add(new_response)
    
    db.session.commit()
    return jsonify({"message": "Respuesta guardada exitosamente"}), 201

# Ruta para obtener las respuestas guardadas
@app.route('/questionnaires/responses/<int:evaluator_id>/<int:test_id>', methods=['GET'])
def get_saved_responses(evaluator_id, test_id):
    responses = EvaluatorResponse.query.filter_by(evaluator_id=evaluator_id, test_id=test_id).all()

    if not responses:
        return jsonify([]), 200

    responses_data = [
        {
            'questionnaire_id': r.questionnaire_id,
            'response_value': r.response_value,
            'respuesta': r.respuesta
        }
        for r in responses
    ]
    return jsonify(responses_data), 200

# Ruta para verificar si fueron guardadas todas las preguntas de los cuestionarios
@app.route('/designtests/<int:test_id>/check_submission', methods=['GET'])
def check_submission(test_id):
    evaluator_id = request.args.get('evaluator_id')
    access = EvaluatorAccess.query.filter_by(evaluator_id=evaluator_id, test_id=test_id).first()
    if access and access.acceso_bloqueado:
        return jsonify({"submitted": True}), 200
    return jsonify({"submitted": False}), 200

# Ruta para enviar todas las respuestas y bloquear el acceso a la prueba de diseño
@app.route('/submit_responses', methods=['POST'])
def submit_responses():
    data = request.json
    evaluator_id = data['evaluator_id']
    test_id = data['test_id']

    access = EvaluatorAccess.query.filter_by(evaluator_id=evaluator_id, test_id=test_id).first()
    if access:
        access.acceso_bloqueado = True
        db.session.commit()
    else:
        return jsonify({"message": "Acceso no encontrado"}), 404

    responses = EvaluatorResponse.query.filter_by(questionnaire_id=test_id, evaluator_id=evaluator_id).all()
    responses_data = [
        {
            'response_id': r.response_id,
            'response_value': r.response_value,
            'respuesta': r.respuesta,
            'created_at': r.created_at,
            'response_type': r.response_type
        }
        for r in responses
    ]
    return jsonify({"message": "Respuestas enviadas y acceso bloqueado"}), 200

#//////////////////////////////////////////////////////////////////////
#//////////////////////////////////////////////////////////////////////

# Ruta para ver todas las respuestas por prueba de diseño
@app.route('/designtests/<int:test_id>/responses', methods=['GET'])
def get_design_test_responses(test_id):
    responses = []
    questionnaires = DesignQuestionnaires.query.filter_by(test_id=test_id).all()

    for questionnaire in questionnaires:
        question_responses = EvaluatorResponse.query.filter_by(questionnaire_id=questionnaire.questionnaire_id).all()
        for response in question_responses:
            evaluator = User.query.get(response.evaluator_id)
            responses.append({
                'response_id': response.response_id,
                'evaluator_id': response.evaluator_id,
                'evaluator_username': evaluator.username,
                'questionnaire_title': questionnaire.title,
                'questionnaire_description': questionnaire.description,
                'url_frame': questionnaire.url_frame,
                'response_value': response.response_value,
                'respuesta': response.respuesta,
                'created_at': response.created_at
            })
    return jsonify(responses), 200

# #/////////////////////////////////////////////////////////////////////////////////////////////////

# Ruta para obtener todos los HeuristicOwners
@app.route('/owners', methods=['GET'])
def get_owners():
    owners = HeuristicOwner.query.all()
    owners_list = []
    for owner in owners:
        owners_list.append({
            'id': owner.id,
            'name': owner.name,
            'url': owner.url,
            'description': owner.description
        })
    return jsonify({'owners': owners_list}), 200


# Ruta para crear un nuevo HeuristicOwner
@app.route('/owners', methods=['POST'])
def create_owner():
    data = request.get_json()
    new_owner = HeuristicOwner(name=data['name'], url=data['url'], description=data['description'])
    print(new_owner.__dict__)
    db.session.add(new_owner)
    db.session.commit()
    return jsonify({'message': 'HeuristicOwner creado correctamente'}), 201


# Ruta para eliminar un HeuristicOwner por ID
@app.route('/owners/<int:id>', methods=['DELETE'])
def delete_owner(id):
    owner = HeuristicOwner.query.get(id)
    if not owner:
        return jsonify({'message': 'HeuristicOwner no encontrado'}), 404

    db.session.delete(owner)
    db.session.commit()
    return jsonify({'message': 'HeuristicOwner eliminado correctamente'}), 200


# Ruta para crear un nuevo HeuristicCheckList asociado a un owner
@app.route('/heuristics', methods=['POST'])
def create_heuristic():
    data = request.get_json()
    owner_id = data.get('owner_id')

    owner = HeuristicOwner.query.get(owner_id)
    if not owner:
        return jsonify({"message": "Owner not found!"}), 404

    heuristic = HeuristicCheckList(owner=owner, **data)
    db.session.add(heuristic)
    db.session.commit()

    return jsonify({"message": "Created successfully!", "id": heuristic.id}), 201

# ruta para solicitud GET para identificar problemas relacionados con un propietario de diseño específico identificado por owner_id
@app.route('/identifyproblems/<int:owner_id>', methods=['GET'])
def identify_problems(owner_id):
    print(owner_id)
    heuristics = HeuristicCheckList.query.filter_by(owner_id=owner_id).all()
    # print(heuristics)
    heuristics_list = []
    for heuristic in heuristics:
        heuristics_list.append({

            'H01P01': heuristic.H01P01,
            'H01P02': heuristic.H01P02,
            'H01P03': heuristic.H01P03,
            'H01P04': heuristic.H01P04,
            'H01P05': heuristic.H01P05,
            'H01P06': heuristic.H01P06,
            'H01P07': heuristic.H01P07,
            'H02P01': heuristic.H02P01,
            'H02P02': heuristic.H02P02,
            'H02P03': heuristic.H02P03,
            'H02P04': heuristic.H02P04,
            'H02P05': heuristic.H02P05,
            'H02P06': heuristic.H02P06,
            'H02P07': heuristic.H02P07,
            'H02P08': heuristic.H02P08,
            'H03P01': heuristic.H03P01,
            'H03P02': heuristic.H03P02,
            'H03P03': heuristic.H03P03,
            'H03P04': heuristic.H03P04,
            'H03P05': heuristic.H03P05,
            'H03P06': heuristic.H03P06,
            'H04P01': heuristic.H04P01,
            'H04P02': heuristic.H04P02,
            'H04P03': heuristic.H04P03,
            'H04P04': heuristic.H04P04,
            'H04P05': heuristic.H04P05,
            'H04P06': heuristic.H04P06,
            'H04P07': heuristic.H04P07,
            'H04P08': heuristic.H04P08,
            'H04P09': heuristic.H04P09,
            'H04P10': heuristic.H04P10,
            'H04P11': heuristic.H04P11,
            'H04P12': heuristic.H04P12,
            'H04P13': heuristic.H04P13,
            'H05P01': heuristic.H05P01,
            'H05P02': heuristic.H05P02,
            'H05P03': heuristic.H05P03,
            'H05P04': heuristic.H05P04,
            'H05P05': heuristic.H05P05,
            'H06P01': heuristic.H06P01,
            'H06P02': heuristic.H06P02,
            'H06P03': heuristic.H06P03,
            'H07P01': heuristic.H07P01,
            'H07P02': heuristic.H07P02,
            'H07P03': heuristic.H07P03,
            'H07P04': heuristic.H07P04,
            'H07P05': heuristic.H07P05,
            'H07P06': heuristic.H07P06,
            'H07P07': heuristic.H07P07,
            'H08P01': heuristic.H08P01,
            'H08P02': heuristic.H08P02,
            'H08P03': heuristic.H08P03,
            'H08P04': heuristic.H08P04,
            'H08P05': heuristic.H08P05,
            'H08P06': heuristic.H08P06,
            'H08P07': heuristic.H08P07,
            'H08P08': heuristic.H08P08,
            'H08P09': heuristic.H08P09,
            'H08P10': heuristic.H08P10,
            'H08P11': heuristic.H08P11,
            'H09P01': heuristic.H09P01,
            'H09P02': heuristic.H09P02,
            'H09P03': heuristic.H09P03,
            'H09P04': heuristic.H09P04,
            'H09P05': heuristic.H09P05,
            'H09P06': heuristic.H09P06,
            'H10P01': heuristic.H10P01,
            'H10P02': heuristic.H10P02,
            'H10P03': heuristic.H10P03,
            'H10P04': heuristic.H10P04,
            'H10P05': heuristic.H10P05,
            'H10P06': heuristic.H10P06,
            'H10P07': heuristic.H10P07,
            'H10P08': heuristic.H10P08,
            'H10P09': heuristic.H10P09,

        })
    # print(heuristics_list)

    false_heuristics_count = {}  # Diccionario para almacenar el recuento de heurísticas falsas

    # Iterar sobre la lista de heurísticas y contar las que son falsas
    for heuristics_dict in heuristics_list:
        for heuristic, value in heuristics_dict.items():
            if not value:  # Si el valor es False
                # Incrementar el recuento en el diccionario o inicializarlo en 1 si es la primera vez que se encuentra
                false_heuristics_count[heuristic] = false_heuristics_count.get(heuristic, 0) + 1

    # Imprimir el recuento de heurísticas falsas
    respuesta = []
    hi = [

        "telacreiste",
        "Visibilidad del estado del sistema",
        "Relación entre el sistema y el mundo real",
        "Control y libertad de usuario",
        "Consistencia y Estándares",
        "Prevención de Errores",
        "Minimizar la carga de memoria del usuario",
        "Flexibilidad y eficiencia de uso ",
        "Diseño estético y minimalista",
        "Ayuda al usuario para reconocer, diagnosticar y recuperarse de errores",
        "Ayuda y Documentación",
    ]
    for heuristic, count in false_heuristics_count.items():
        import re

        descripcion = HeuristicDescriptions.query.filter_by(name=heuristic).first().description
        print(descripcion)
        resultado = re.search(r'h(\d+)', heuristic, re.IGNORECASE)
        hfail = ""
        if resultado:
            numero_despues_de_h = resultado.group(1)
            print(int(numero_despues_de_h))
            hfail = hi[int(numero_despues_de_h)]
            print("Número después de 'h':", numero_despues_de_h)
        else:
            print("No se encontró ningún número después de 'h' en la cadena.")

        respuesta.append({"name": heuristic, "description": descripcion, "hi": hfail, "incidents": count})

    print(respuesta)
    return jsonify(respuesta)

#ruta para solicitudes POST para guardar evaluaciones 
@app.route('/evaluations/<int:owner_id>', methods=['POST'])
def saveEvaluations(owner_id):
    data = request.get_json()
    print(owner_id)
    print(data)

    for evaluation in data:
        ev = HeuristicEvaluations(owner_id=owner_id, **evaluation)
        db.session.add(ev)
        db.session.commit()

    return jsonify({"message": "Guardado Correctamente"})

# ruta para recupera evaluaciones de un propietario de diseño específico identificado mediante owner_iduna solicitud GET
@app.route('/evaluations/<int:owner_id>', methods=['GET'])
def getEvaluations(owner_id):
    evaluations = HeuristicEvaluations.query.filter_by(owner_id=owner_id).all()
    print(evaluations)
    response = []
    for evaluation in evaluations:
        response.append({
            'name': evaluation.name,
            'description': evaluation.description,
            'hi': evaluation.hi,
            'incidents': evaluation.incidents,
            'severity': evaluation.severity,
            'frequency': evaluation.frequency,
            'criticism': evaluation.criticism,
        })
    print(response)
    return jsonify(response)

# ruta para  recuperar observaciones asociadas con un ID de propietario 
@app.route('/getobservations/<int:owner_id>')
def get_observations(owner_id):
    heuristics = HeuristicCheckList.query.filter_by(owner_id=owner_id).all()
    print(heuristics)
    heuristics_observations_list = []
    for heuristic in heuristics:
        heuristics_observations_list.append({
            "H1": heuristic.OBSERVACIONH1,
            "H2": heuristic.OBSERVACIONH2,
            "H3": heuristic.OBSERVACIONH3,
            "H4": heuristic.OBSERVACIONH4,
            "H5": heuristic.OBSERVACIONH5,
            "H6": heuristic.OBSERVACIONH6,
            "H7": heuristic.OBSERVACIONH7,
            "H8": heuristic.OBSERVACIONH8,
            "H9": heuristic.OBSERVACIONH9,
            "H10": heuristic.OBSERVACIONH10,
        })
    for h in heuristics_observations_list:
        print(h)
    return jsonify(heuristics_observations_list)


# Ruta para obtener todos los HeuristicCheckLists asociados a un owner
@app.route('/owners/<int:owner_id>/heuristics', methods=['GET'])
def get_owner_heuristics(owner_id):
    owner = HeuristicOwner.query.get(owner_id)
    if not owner:
        return jsonify({"message": "Owner not found!"}), 404

    heuristics = HeuristicCheckList.query.filter_by(owner_id=owner_id).all()
    heuristics_list = []
    for heuristic in heuristics:
        heuristics_list.append({
            'id': heuristic.id,
            'H01P01': heuristic.H01P01,
            'H01P02': heuristic.H01P02,
            'H01P03': heuristic.H01P03,
            'H01P04': heuristic.H01P04,
            'H01P05': heuristic.H01P05,
            'H01P06': heuristic.H01P06,
            'H01P07': heuristic.H01P07,
            'H02P01': heuristic.H02P01,
            'H02P02': heuristic.H02P02,
            'H02P03': heuristic.H02P03,
            'H02P04': heuristic.H02P04,
            'H02P05': heuristic.H02P05,
            'H02P06': heuristic.H02P06,
            'H02P07': heuristic.H02P07,
            'H02P08': heuristic.H02P08,
            'H03P01': heuristic.H03P01,
            'H03P02': heuristic.H03P02,
            'H03P03': heuristic.H03P03,
            'H03P04': heuristic.H03P04,
            'H03P05': heuristic.H03P05,
            'H03P06': heuristic.H03P06,
            'H04P01': heuristic.H04P01,
            'H04P02': heuristic.H04P02,
            'H04P03': heuristic.H04P03,
            'H04P04': heuristic.H04P04,
            'H04P05': heuristic.H04P05,
            'H04P06': heuristic.H04P06,
            'H04P07': heuristic.H04P07,
            'H04P08': heuristic.H04P08,
            'H04P09': heuristic.H04P09,
            'H04P10': heuristic.H04P10,
            'H04P11': heuristic.H04P11,
            'H04P12': heuristic.H04P12,
            'H04P13': heuristic.H04P13,
            'H05P01': heuristic.H05P01,
            'H05P02': heuristic.H05P02,
            'H05P03': heuristic.H05P03,
            'H05P04': heuristic.H05P04,
            'H05P05': heuristic.H05P05,
            'H06P01': heuristic.H06P01,
            'H06P02': heuristic.H06P02,
            'H06P03': heuristic.H06P03,
            'H07P01': heuristic.H07P01,
            'H07P02': heuristic.H07P02,
            'H07P03': heuristic.H07P03,
            'H07P04': heuristic.H07P04,
            'H07P05': heuristic.H07P05,
            'H07P06': heuristic.H07P06,
            'H07P07': heuristic.H07P07,
            'H08P01': heuristic.H08P01,
            'H08P02': heuristic.H08P02,
            'H08P03': heuristic.H08P03,
            'H08P04': heuristic.H08P04,
            'H08P05': heuristic.H08P05,
            'H08P06': heuristic.H08P06,
            'H08P07': heuristic.H08P07,
            'H08P08': heuristic.H08P08,
            'H08P09': heuristic.H08P09,
            'H08P10': heuristic.H08P10,
            'H08P11': heuristic.H08P11,
            'H09P01': heuristic.H09P01,
            'H09P02': heuristic.H09P02,
            'H09P03': heuristic.H09P03,
            'H09P04': heuristic.H09P04,
            'H09P05': heuristic.H09P05,
            'H09P06': heuristic.H09P06,
            'H10P01': heuristic.H10P01,
            'H10P02': heuristic.H10P02,
            'H10P03': heuristic.H10P03,
            'H10P04': heuristic.H10P04,
            'H10P05': heuristic.H10P05,
            'H10P06': heuristic.H10P06,
            'H10P07': heuristic.H10P07,
            'H10P08': heuristic.H10P08,
            'H10P09': heuristic.H10P09,
            'OBSERVACIONH1': heuristic.OBSERVACIONH1,
            'OBSERVACIONH2': heuristic.OBSERVACIONH3,
            'OBSERVACIONH3': heuristic.OBSERVACIONH3,
            'OBSERVACIONH4': heuristic.OBSERVACIONH4,
            'OBSERVACIONH5': heuristic.OBSERVACIONH5,
            'OBSERVACIONH6': heuristic.OBSERVACIONH6,
            'OBSERVACIONH7': heuristic.OBSERVACIONH7,
            'OBSERVACIONH8': heuristic.OBSERVACIONH8,
            'OBSERVACIONH9': heuristic.OBSERVACIONH9,
            'OBSERVACIONH10': heuristic.OBSERVACIONH10,
        })

    return jsonify({'heuristics': heuristics_list}), 200

# ruta para recuperar una heurística específica de la base de datos en función de su ID
@app.route('/heuristic/<int:id>')
def getheuristicbyid(id):
    heuristic = HeuristicCheckList.query.get(id)
    if not heuristic:
        return jsonify({"message": "heuristic not found!"}), 404
    return jsonify({
        'id': heuristic.id,
        'H01P01': heuristic.H01P01,
        'H01P02': heuristic.H01P02,
        'H01P03': heuristic.H01P03,
        'H01P04': heuristic.H01P04,
        'H01P05': heuristic.H01P05,
        'H01P06': heuristic.H01P06,
        'H01P07': heuristic.H01P07,
        'H02P01': heuristic.H02P01,
        'H02P02': heuristic.H02P02,
        'H02P03': heuristic.H02P03,
        'H02P04': heuristic.H02P04,
        'H02P05': heuristic.H02P05,
        'H02P06': heuristic.H02P06,
        'H02P07': heuristic.H02P07,
        'H02P08': heuristic.H02P08,
        'H03P01': heuristic.H03P01,
        'H03P02': heuristic.H03P02,
        'H03P03': heuristic.H03P03,
        'H03P04': heuristic.H03P04,
        'H03P05': heuristic.H03P05,
        'H03P06': heuristic.H03P06,
        'H04P01': heuristic.H04P01,
        'H04P02': heuristic.H04P02,
        'H04P03': heuristic.H04P03,
        'H04P04': heuristic.H04P04,
        'H04P05': heuristic.H04P05,
        'H04P06': heuristic.H04P06,
        'H04P07': heuristic.H04P07,
        'H04P08': heuristic.H04P08,
        'H04P09': heuristic.H04P09,
        'H04P10': heuristic.H04P10,
        'H04P11': heuristic.H04P11,
        'H04P12': heuristic.H04P12,
        'H04P13': heuristic.H04P13,
        'H05P01': heuristic.H05P01,
        'H05P02': heuristic.H05P02,
        'H05P03': heuristic.H05P03,
        'H05P04': heuristic.H05P04,
        'H05P05': heuristic.H05P05,
        'H06P01': heuristic.H06P01,
        'H06P02': heuristic.H06P02,
        'H06P03': heuristic.H06P03,
        'H07P01': heuristic.H07P01,
        'H07P02': heuristic.H07P02,
        'H07P03': heuristic.H07P03,
        'H07P04': heuristic.H07P04,
        'H07P05': heuristic.H07P05,
        'H07P06': heuristic.H07P06,
        'H07P07': heuristic.H07P07,
        'H08P01': heuristic.H08P01,
        'H08P02': heuristic.H08P02,
        'H08P03': heuristic.H08P03,
        'H08P04': heuristic.H08P04,
        'H08P05': heuristic.H08P05,
        'H08P06': heuristic.H08P06,
        'H08P07': heuristic.H08P07,
        'H08P08': heuristic.H08P08,
        'H08P09': heuristic.H08P09,
        'H08P10': heuristic.H08P10,
        'H08P11': heuristic.H08P11,
        'H09P01': heuristic.H09P01,
        'H09P02': heuristic.H09P02,
        'H09P03': heuristic.H09P03,
        'H09P04': heuristic.H09P04,
        'H09P05': heuristic.H09P05,
        'H09P06': heuristic.H09P06,
        'H10P01': heuristic.H10P01,
        'H10P02': heuristic.H10P02,
        'H10P03': heuristic.H10P03,
        'H10P04': heuristic.H10P04,
        'H10P05': heuristic.H10P05,
        'H10P06': heuristic.H10P06,
        'H10P07': heuristic.H10P07,
        'H10P08': heuristic.H10P08,
        'H10P09': heuristic.H10P09,
        'OBSERVACIONH1': heuristic.OBSERVACIONH1,
        'OBSERVACIONH2': heuristic.OBSERVACIONH2,
        'OBSERVACIONH3': heuristic.OBSERVACIONH3,
        'OBSERVACIONH4': heuristic.OBSERVACIONH4,
        'OBSERVACIONH5': heuristic.OBSERVACIONH5,
        'OBSERVACIONH6': heuristic.OBSERVACIONH6,
        'OBSERVACIONH7': heuristic.OBSERVACIONH7,
        'OBSERVACIONH8': heuristic.OBSERVACIONH8,
        'OBSERVACIONH9': heuristic.OBSERVACIONH9,
        'OBSERVACIONH10': heuristic.OBSERVACIONH10,
    })


# Ruta para obtener un HeuristicCheckList por ID asociado a un owner
@app.route('/owners/<int:owner_id>/heuristics/<int:id>', methods=['GET'])
def get_owner_heuristic(owner_id, id):
    owner = HeuristicOwner.query.get(owner_id)
    if not owner:
        return jsonify({"message": "Owner not found!"}), 404

    heuristic = HeuristicCheckList.query.filter_by(owner_id=owner_id, id=id).first()
    if not heuristic:
        return jsonify({"message": "HeuristicCheckList not found!"}), 404

    return jsonify({
        'id': heuristic.id,
        'OBSERVACIONES': heuristic.OBSERVACIONES,

    }), 200


# Ruta para obtener un HeuristicOwner por ID
@app.route('/owners/<int:id>', methods=['GET'])
def get_owner(id):
    owner = HeuristicOwner.query.get(id)
    if not owner:
        return jsonify({'message': 'HeuristicOwner no encontrado'}), 404
    owner_data = {
        'id': owner.id,
        'name': owner.name,
        'url': owner.url,
        'description': owner.description,
    }
    return jsonify(owner_data), 200


# Ruta para actualizar un HeuristicOwner por ID
@app.route('/owners/<int:id>', methods=['PUT'])
def update_owner(id):
    owner = HeuristicOwner.query.get(id)
    if not owner:
        return jsonify({'message': 'HeuristicOwner no encontrado'}), 404

    data = request.get_json()
    owner.Name = data['name']
    owner.Url = data['url']
    db.session.commit()
    return jsonify({'message': 'HeuristicOwner actualizado correctamente'}), 200


###########################################################################

# Ruta para registrar un nuevo usuario

@app.route('/register', methods=['POST'])
def register_user():
    data = request.json
    username = data['username']
    email = data['email']
    password = data['password']
    rol = data['rol']
    experience = data['experience']  # Asegúrate de enviar este campo desde el frontend

    # Verifica si el rol seleccionado es válido
    if rol not in ['administrator', 'owner', 'evaluator']:
        return jsonify({'message': 'Invalid role selected'}), 400

    # Verificar si el usuario o el correo ya están en uso
    if User.query.filter_by(username=username).first() is not None:
        return jsonify({'message': 'El nombre de usuario ya está en uso'}), 400
    if User.query.filter_by(email=email).first() is not None:
        return jsonify({'message': 'El correo electrónico ya está en uso'}), 400

    # Crea un nuevo usuario con los datos proporcionados
    new_user = User(username=username, email=email, rol=rol, experience=experience)
    new_user.set_password(password)

    # Agrega el nuevo usuario a la base de datos y guarda los cambios
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Usuario registrado correctamente'}), 201



# Ruta para iniciar sesión
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    user = User.query.filter_by(username=data['username']).first()

    if user and user.check_password(data['password']):
        # login_user(user)
        user_data={  'id': user.id,
        'username': user.username,
        'email': user.email,
        'rol': user.rol,}
        return jsonify({'message': 'Inicio de sesión exitoso','user':user_data}), 200
    else:
        return jsonify({'message': 'Credenciales incorrectas'}), 401


# Ruta para cerrar sesión
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Sesión cerrada correctamente'}), 200


# Ruta para obtener información del usuario actual
@app.route('/user', methods=['GET'])
@login_required
def get_current_user():
    if current_user.rol == 'evaluator':
        experience = current_user.experience
    else:
        experience = None
    
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'email': current_user.email,
        'rol': current_user.rol,
        'experience': experience
    }), 200


@app.route('/register', methods=['OPTIONS'])
def handle_options():
    return jsonify({'message': 'OK'}), 200


if __name__ == '__main__':
    with app.app_context():
        print("recreando base de datos")
        db.create_all()
    app.run(debug=True)
