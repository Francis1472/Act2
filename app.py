from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt


app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///al.db'
app.config['SECRET_KEY'] = 'laksdjflkjasdf'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    
class RegisterForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    user = db.relationship('Item', backref='user')
    
class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner = db.Column(db.Integer, db.ForeignKey('user.id'))
    product = db.Column(db.String(200), nullable=False)
    purchased = db.Column(db.Boolean)
    date_created = db.Column(db.DateTime, default=datetime.utcnow) 

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    items = db.Column(db.String(200), nullable=False)    
    item_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    sold = db.Column(db.Integer)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)  
    
    def __repr__(self):
        return '<Items %r>' % self.id

@app.route('/', methods=['POST', 'GET'])
def index():    
    if current_user.is_authenticated:
        return redirect('/home')
    
    if request.method == 'POST':
        item_content = request.form['item']
        new_item = Item(items=item_content)
        
        try:
            db.session.add(new_item)
            db.session.commit()
            return redirect('/')
        except:
            return 'There was an issue'

    else:
        items = Item.query.order_by(Item.date_created).all()
        return render_template('index.html', items=items)

@app.route('/delete/<int:id>')
def delete(id):
    item_delete = Item.query.get_or_404(id)

    try:
        db.session.delete(item_delete)
        db.session.commit()
        return redirect('/home/manageProducts')
    except:
        return 'There was a problem Deleting'
        

    
@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
    item = Item.query.get_or_404(id)
    
    if request.method == 'POST':
                
        if item.item_id != current_user.id:
            return 'no permission'
        
        else:                
            item.items = request.form['item']
            
            try:
                db.session.commit()
                return redirect('/home/manageProducts')
            except:
                return 'There was an issues updating'
    else:
        return render_template('update.html', item=item)
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect('/home')
        
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('home'))
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect('/')

@app.route('/home', methods=['POST', 'GET'])
@login_required
def home():   
    if request.method == 'POST':
        item = request.form['item']
        data = Item(items=item, item_id=current_user.id)

        try:
            db.session.add(data)
            db.session.commit()
            return redirect('/home/manageProducts')
        except:
            return 'There was an issue'

    else:
        items = Item.query.order_by(Item.date_created).all()
        user = current_user.id        
        return render_template('home.html', items=items, user=user)

@ app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect('/home')
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/home/manageProducts', methods=['POST', 'GET'])
@login_required
def mProducts():
    if request.method == 'POST':
        item = request.form['item']
        data = Item(items=item, item_id=current_user.id, sold=0)

        try:
            db.session.add(data)
            db.session.commit()
            return redirect('/home/manageProducts')
        except:
            return 'There was an issue'

    else:
        user = current_user.id        
        items = Item.query.filter_by(item_id=user).all()
        return render_template('manageProducts.html', items=items)
    
@app.route('/home/AddtoCart/<int:id>', methods=['POST', 'GET'])
@login_required
def AddtoCart(id):
    item = Item.query.get_or_404(id)
    
    Owner = current_user.id
    Product = item.items
    data = Cart(owner=Owner, product=Product, purchased=False)
    
    try:
        db.session.add(data)
        db.session.commit()
        return redirect('/home')
    except:
        return 'There was an issue' 
    
@app.route('/home/cart', methods=['POST', 'GET'])
@login_required
def cart():    
    user = current_user.id
    purchased = Cart.purchased
    Products = Cart.query.filter_by(owner=user).order_by(purchased).all()
    
    return render_template('cart.html', items=Products)

@app.route('/home/cart/delete/<int:id>', methods=['POST', 'GET'])
@login_required
def delCart(id):
    delCartItem = Cart.query.get_or_404(id)
    
    try:
        db.session.delete(delCartItem)
        db.session.commit()
        
        return redirect('/home/cart')
    except:
        return 'problem Deleting Cart'
    
@app.route('/home/buy/<int:id>', methods=['POST', 'GET'])
@login_required
def buy(id):
    cart = Cart.query.filter_by(id=id).first()
    sold = Item.query.first()
    sold.sold = Item.sold + 1
    
    if request.method == 'GET':        
        cart.purchased = True
        
        try:        
            db.session.commit()
            return redirect('/home/cart')
        except:
            return 'There was an issue'

if __name__ == "__main__":
    app.run(debug=True)
