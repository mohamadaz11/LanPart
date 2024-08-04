from flask import Flask, request
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Resource, Api
from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity


# Initialize the app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lanparty.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'somethinghard'



# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
api = Api(app)


# Database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    scores = db.relationship('GameScore', backref='user', lazy=True)

class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    scores = db.relationship('GameScore', backref='game', lazy=True)

class GameScore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    score = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    game_id = db.Column(db.Integer, db.ForeignKey('game.id'), nullable=False)


with app.app_context():
    db.create_all()


# End points
class Register(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return {'message': 'you missed username or password. come on man it is not rocket science'}, 400

        if User.query.filter_by(username=username).first():
            return {'message': 'username already taken. be original maaaan'}, 409

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return {'message': 'nice you have enough brain cells to create a new user successfully'}, 201


class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return {'message': 'you know you have to put all the required info right?'}, 400

        user = User.query.filter_by(username=username).first()
        if not user or not bcrypt.check_password_hash(user.password, password):
            return {'message': 'seems like someone forgot his login data'}, 401

        access_token = create_access_token(identity={'user_id': user.id})
        return {'access_token': access_token, 'message': 'You’re logged in. Now, please try not to break anything.'}, 200


class AddGame(Resource):
    @jwt_required()
    def post(self):
        data = request.get_json()
        name = data.get('name')

        if not name:
            return {'message': 'Seriously? You forgot to provide a game name? Try again.'}, 400

        if Game.query.filter_by(name=name.lower()).first():
            return {'message': 'This game already exists. Maybe you need to pay more attention?'}, 409

        new_game = Game(name=name.lower())
        db.session.add(new_game)
        db.session.commit()

        return {'message': 'Game added. Try not to mess it up.'}, 201


class AddScore(Resource):
    @jwt_required()
    def post(self):
        data = request.get_json()
        game_name = data.get('game')
        score = data.get('score')

        if not game_name or not score:
            return {'message': 'Really? Missing game name or score? This is basic stuff.'}, 400

        game = Game.query.filter_by(name=game_name.lower()).first()
        if not game:
            return {'message': 'Game not found. Maybe it’s hiding from you? just like your father who went to buy milk'}, 404

        user_id = get_jwt_identity()['user_id']
        new_score = GameScore(score=score, user_id=user_id, game_id=game.id)
        db.session.add(new_score)
        db.session.commit()

        return {'message': 'Score added. We’re all so impressed. get a life'}, 201


class GetGames(Resource):
    def get(self):
        try:
            games = Game.query.all()
            if not games:
                return {'message': 'Surprisingly, there are no games in the database. Shocking, right?'}, 404

            result = [{'id': game.id, 'name': game.name} for game in games]
            return (result)
        except Exception as e:
            return ({'message': f'Something went wrong: {str(e)}. Maybe you should try something simpler.'}), 500


class HighScores(Resource):
    def get(self):
        try:
            scores = db.session.query(
                User.username,
                db.func.sum(GameScore.score).label('total_score')
            ) \
                .join(GameScore, User.id == GameScore.user_id) \
                .group_by(User.id) \
                .order_by(db.func.sum(GameScore.score).desc()) \
                .all()

            result = [{'user': username, 'total_score': total_score} for username, total_score in scores]

            return (result), 200
        except Exception as e:
            return {'message': str(e)}, 500


# Add resources to the API
api.add_resource(Register, '/register')
api.add_resource(Login, '/login')
api.add_resource(AddGame, '/add_game')
api.add_resource(AddScore, '/add_score')
api.add_resource(GetGames, '/games')
api.add_resource(HighScores, '/highscores')



if __name__ == '__main__':
    app.run(debug=True)