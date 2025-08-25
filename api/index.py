import os
import re
import io
from flask import Flask, render_template, request, redirect, url_for, flash, session, Response, send_file
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import Markup, escape
from pymongo import MongoClient
from bson.objectid import ObjectId
import requests
from dotenv import load_dotenv
from math import ceil
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.enums import TA_CENTER
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import json
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from datetime import datetime, timedelta
import secrets

load_dotenv()
styles = getSampleStyleSheet()

def get_base_url():
    root = request.url_root
    if root.endswith('/'):
        return root[:-1]
    return root

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.join(current_dir, "..")

app = Flask(__name__, root_path=project_root, template_folder="templates")
app.static_folder = 'static'

app.secret_key = os.getenv('SECRET_KEY')
if not app.secret_key:
    print("Warning: SECRET_KEY not set. Session will not be secure.")
    app.secret_key = 'temporary_insecure_key_for_dev_only'

s = URLSafeTimedSerializer(app.secret_key)

MONGO_URI = os.getenv('MONGO_URI')
if not MONGO_URI:
    raise ValueError("MONGO_URI environment variable not set. Please set it in Vercel.")

client = MongoClient(MONGO_URI)
db = client['test_db']
products_collection = db['products']
users_collection = db['users']
reviews_collection = db['reviews']

IMGUR_CLIENT_ID = os.getenv('IMGUR_CLIENT_ID')
if not IMGUR_CLIENT_ID:
    print("Warning: IMGUR_CLIENT_ID not set. Imgur upload will not work.")
IMGUR_UPLOAD_URL = "https://api.imgur.com/3/image"

def upload_single_image_to_imgur(image_file_stream):
    if not IMGUR_CLIENT_ID:
        flash("Imgur Client ID tidak diatur, unggah gambar tidak berfungsi.", 'danger')
        return None
    if not image_file_stream:
        return None

    headers = {'Authorization': f'Client-ID {IMGUR_CLIENT_ID}'}
    files = {'image': image_file_stream.read()}

    try:
        response = requests.post(IMGUR_UPLOAD_URL, headers=headers, files=files)
        response.raise_for_status()
        data = response.json()
        if data['success']:
            return data['data']['link']
        else:
            print(f"Imgur upload error: {data.get('data', {}).get('error', 'Unknown error')}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Connection error during Imgur upload: {e}")
        return None

GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')

print(f"Debug: GOOGLE_CLIENT_ID from .env: {GOOGLE_CLIENT_ID}")
print(f"Debug: GOOGLE_CLIENT_SECRET from .env: {GOOGLE_CLIENT_SECRET}")

if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    print("Warning: GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET not set. Google Sign-In will not work.")

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() in ('true', '1', 't')
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'False').lower() in ('true', '1', 't')
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mail = Mail(app)

if 'Title' not in styles:
    styles.add(ParagraphStyle(name='Title', fontSize=18, leading=22, alignment=1, spaceAfter=20))

basedir = os.path.abspath(os.path.dirname(__file__))

roboto_regular_path = os.path.join(basedir, 'Roboto-Regular.ttf')
roboto_bold_path = os.path.join(basedir, 'Roboto-Bold.ttf')

pdfmetrics.registerFont(TTFont('Roboto', roboto_regular_path))
pdfmetrics.registerFont(TTFont('Roboto-Bold', roboto_bold_path))

def send_receipt_email(order_id, recipient_email):
    try:
        receipt_pdf = create_receipt_pdf_data(order_id)
        
        if not receipt_pdf:
            print("Gagal membuat data PDF struk.")
            return

        msg = Message(
            subject=f'Struk Pembelian Anda - Pesanan #{str(order_id)}',
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[recipient_email]
        )
        msg.body = f"""
Halo,

Terima kasih telah berbelanja di toko kami!
Berikut adalah struk pembelian Anda untuk pesanan dengan nomor #{str(order_id)}.

Silakan cek lampiran email ini.

Terima kasih,
Tim Box Phone
"""
        msg.attach(f'struk_pembelian_{str(order_id)}.pdf', 'application/pdf', receipt_pdf)
        mail.send(msg)
        print(f"Struk pesanan {str(order_id)} berhasil dikirim ke {recipient_email}")
        
    except Exception as e:
        print(f"Gagal mengirim email struk untuk pesanan {str(order_id)}: {e}")

@app.template_filter('nl2br')
def nl2br_filter(s):
    if s is None:
        return ''
    return Markup(s.replace('\n', '<br>'))

@app.template_filter('escapejs')
def escapejs_filter(s):
    if s is None:
        return ''
    return escape(s).replace("'", "\\'").replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')

@app.before_request
def initialize_session_variables():
    if 'cart' not in session:
        session['cart'] = {}
    
    if 'user_id' not in session:
        session['user_id'] = None
    if 'username' not in session:
        session['username'] = None
    if 'is_admin' not in session:
        session['is_admin'] = False
    if 'is_customer' not in session:
        session['is_customer'] = False

    app.jinja_env.globals['current_logged_in_user'] = session.get('username')
    app.jinja_env.globals['is_admin_logged_in'] = session.get('is_admin')
    app.jinja_env.globals['is_customer_logged_in'] = session.get('is_customer')

def admin_required(f):
    def wrap(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Anda tidak memiliki izin untuk mengakses halaman ini.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

def login_required(f):
    def wrap(*args, **kwargs):
        if not session.get('user_id'):
            flash('Anda harus login untuk mengakses halaman ini.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

@app.context_processor
def inject_google_client_id():
    return dict(GOOGLE_CLIENT_ID=GOOGLE_CLIENT_ID)

@app.context_processor
def inject_cart_count():
    cart_count = sum(item['quantity'] for item in session.get('cart', {}).values())
    return dict(cart_count=cart_count)

PER_PAGE = 3

@app.route('/')
def index():
    selected_category_param = request.args.get('category')
    search_query = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)

    query = {}
    selected_category_for_template = selected_category_param

    if selected_category_param and selected_category_param not in ['all', 'None']:
        query['category'] = selected_category_param
    else:
        selected_category_for_template = 'all'

    if search_query:
        query['name'] = {'$regex': re.compile(search_query, re.IGNORECASE)}

    total_products = products_collection.count_documents(query)
    total_pages = ceil(total_products / PER_PAGE)
    
    if total_pages > 0 and page > total_pages:
        page = total_pages
    elif total_pages == 0:
        page = 1

    skip_count = (page - 1) * PER_PAGE
    
    products = list(products_collection.find(query).skip(skip_count).limit(PER_PAGE))
    
    all_categories = sorted(list(set(p['category'] for p in products_collection.find({}, {'category': 1}) if p.get('category'))))

    print(f"MongoDB Query: {query}, Page: {page}, Skip: {skip_count}, Limit: {PER_PAGE}, Total Products: {total_products}")

    return render_template('index.html', 
                           products=products, 
                           all_categories=all_categories, 
                           selected_category=selected_category_for_template,
                           search_query=search_query,
                           current_page=page,
                           total_pages=total_pages,
                           total_products=total_products)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user_id'):
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = users_collection.find_one({
            '$or': [
                {'username': username},
                {'email': username}
            ]
        })

        if user:
            if 'google_id' in user and 'password' not in user:
                flash('Anda terdaftar dengan Google. Mohon gunakan tombol "Login dengan Google".', 'info')
                return redirect(url_for('login'))
            
            if 'password' in user and check_password_hash(user['password'], password):
                session['user_id'] = str(user['_id'])
                session['username'] = user['username']
                session['is_admin'] = (user.get('role') == 'admin')
                session['is_customer'] = (user.get('role') == 'customer')
                session.modified = True
                flash('Login berhasil!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Username atau kata sandi salah.', 'danger')
        else:
            flash('Username atau kata sandi salah.', 'danger')
    
    return render_template('auth/login.html', GOOGLE_CLIENT_ID=GOOGLE_CLIENT_ID)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('user_id'):
        flash('Anda sudah login.', 'info')
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        
        if not username or not password:
            flash('Nama pengguna dan kata sandi tidak boleh kosong.', 'danger')
            return render_template('register.html')
        
        if users_collection.find_one({'username': username}):
            flash('Nama pengguna sudah ada. Pilih nama pengguna lain.', 'warning')
            return render_template('auth/register.html')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        users_collection.insert_one({
            'username': username,
            'password': hashed_password,
            'role': 'customer'
        })
        flash(f'Akun "{username}" berhasil dibuat! Silakan login.', 'success')
        return redirect(url_for('login'))
    return render_template('auth/register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('is_admin', None)
    session.pop('is_customer', None)
    flash('Anda telah berhasil logout.', 'info')
    return redirect(url_for('index'))

@app.route('/create_first_admin', methods=['GET', 'POST'])
def create_first_admin():
    if users_collection.find_one({'role': 'admin'}):
        flash('Admin sudah ada. Anda tidak bisa membuat admin baru dari sini.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        
        if not username or not password:
            flash('Nama pengguna dan kata sandi tidak boleh kosong.', 'danger')
            return render_template('auth/create_first_admin.html')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        users_collection.insert_one({
            'username': username,
            'password': hashed_password,
            'role': 'admin'
        })
        flash(f'Akun admin "{username}" berhasil dibuat! Silakan login.', 'success')
        return redirect(url_for('login'))
    return render_template('auth/create_first_admin.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = users_collection.find_one({'username': email, 'role': {'$in': ['admin', 'customer']}})
        
        if user:
            token = s.dumps(str(user['_id']), salt='password-reset-salt')
            
            expiry_time = datetime.now() + timedelta(hours=1)
            users_collection.update_one(
                {'_id': user['_id']},
                {'$set': {'reset_token': token, 'reset_token_expiry': expiry_time}}
            )

            reset_url = url_for('reset_password', token=token, _external=True)
            
            try:
                msg = Message(
                    'Permintaan Reset Sandi Anda',
                    sender=app.config['MAIL_DEFAULT_SENDER'],
                    recipients=[email]
                )
                msg.body = f"""Halo,

Anda telah meminta reset sandi untuk akun Anda.
Untuk mengatur ulang sandi Anda, kunjungi tautan berikut:

{reset_url}

Tautan ini akan kedaluwarsa dalam 1 jam.

Jika Anda tidak meminta reset sandi, abaikan email ini.

Terima kasih,
Tim Box Phone
"""
                mail.send(msg)
                flash('Link reset sandi telah dikirim ke email Anda. Silakan cek kotak masuk Anda (termasuk folder spam).', 'info')
            except Exception as e:
                flash(f'Gagal mengirim email reset sandi. Pastikan konfigurasi email sudah benar. Error: {e}', 'danger')
                print(f"Mail sending error: {e}")
        else:
            flash('Email tidak ditemukan atau tidak terdaftar sebagai customer.', 'danger')
        
        return redirect(url_for('forgot_password'))
    
    return render_template('auth/forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        user_id_str = s.loads(token, salt='password-reset-salt', max_age=3600)
        user = users_collection.find_one({'_id': ObjectId(user_id_str)})

        if not user or user.get('reset_token') != token or user.get('reset_token_expiry') < datetime.now():
            flash('Tautan reset sandi tidak valid atau telah kedaluwarsa.', 'danger')
            return redirect(url_for('login'))

    except (SignatureExpired, BadTimeSignature):
        flash('Tautan reset sandi telah kedaluwarsa atau tidak valid.', 'danger')
        return redirect(url_for('login'))
    except Exception as e:
        flash('Terjadi kesalahan dengan tautan reset sandi Anda.', 'danger')
        print(f"Error loading reset token: {e}")
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or not confirm_password:
            flash('Sandi baru dan konfirmasi sandi diperlukan.', 'danger')
            return render_template('auth/reset_password.html', token=token)

        if new_password != confirm_password:
            flash('Sandi baru dan konfirmasi sandi tidak cocok.', 'danger')
            return render_template('auth/reset_password.html', token=token)
        
        if len(new_password) < 6:
            flash('Kata sandi harus minimal 6 karakter.', 'danger')
            return render_template('auth/reset_password.html', token=token)

        hashed_password = generate_password_hash(new_password)
        users_collection.update_one(
            {'_id': user['_id']},
            {'$set': {'password': hashed_password},
             '$unset': {'reset_token': '', 'reset_token_expiry': ''}}
        )
        
        flash('Sandi Anda berhasil direset. Silakan login dengan sandi baru Anda.', 'success')
        return redirect(url_for('login'))

    return render_template('auth/reset_password.html', token=token)

@app.route('/google_callback', methods=['POST'])
def google_callback():
    if not GOOGLE_CLIENT_ID:
        flash("Google Client ID tidak diatur.", 'danger')
        return redirect(url_for('login'))

    try:
        id_token_str = request.form.get('credential')
        if not id_token_str:
            raise ValueError("ID token tidak ditemukan.")

        idinfo = id_token.verify_oauth2_token(id_token_str, google_requests.Request(), GOOGLE_CLIENT_ID)

        if idinfo['aud'] not in [GOOGLE_CLIENT_ID]:
            raise ValueError('Audience mismatch.')

        google_user_id = idinfo['sub']
        email = idinfo.get('email')
        name = idinfo.get('name') or email

        if not email:
            flash("Email tidak ditemukan di token Google.", 'danger')
            return redirect(url_for('login'))

        user = users_collection.find_one({
            '$or': [
                {'google_id': google_user_id},
                {'email': email}
            ]
        })

        if user:
            if 'google_id' not in user:
                users_collection.update_one(
                    {'_id': user['_id']},
                    {'$set': {'google_id': google_user_id}}
                )
                user['google_id'] = google_user_id
                flash(f'Akun Anda ({email}) berhasil dihubungkan dengan Google.', 'success')
            else:
                flash(f'Selamat datang kembali, {name or email}!', 'success')
        else:
            user_data = {
                'username': email,
                'email': email,
                'name': name,
                'google_id': google_user_id,
                'role': 'customer'
            }
            users_collection.insert_one(user_data)
            user = users_collection.find_one({'google_id': google_user_id})
            flash(f'Selamat datang, {name}! Akun Anda berhasil dibuat dengan Google.', 'success')
        
        session['user_id'] = str(user['_id'])
        session['username'] = user['username']
        session['is_admin'] = (user.get('role') == 'admin')
        session['is_customer'] = (user.get('role') == 'customer')
        session.modified = True

        return redirect(url_for('index'))

    except ValueError as e:
        flash(f"Kesalahan verifikasi Google Sign-In: {e}", 'danger')
        print(f"Google Sign-In Error: {e}")
        return redirect(url_for('login'))
    except Exception as e:
        flash(f"Terjadi kesalahan saat login dengan Google: {e}", 'danger')
        print(f"Unhandled Google Sign-In Exception: {e}")
        return redirect(url_for('login'))
    
@app.route('/product/<id>')
def product_detail(id):
    product = products_collection.find_one({'_id': ObjectId(id)})
    if product:
        if 'image_url' in product and not isinstance(product.get('image_urls'), list):
            product['image_urls'] = [product['image_url']]
        elif 'image_urls' not in product:
            product['image_urls'] = []

        reviews = list(reviews_collection.find({'product_id': ObjectId(id)}).sort('created_at', -1))

        logged_in_username = session.get('username')
        is_admin_logged_in = session.get('is_admin', False)

        return render_template('product_detail.html', 
                               product=product, 
                               logged_in_username=logged_in_username, 
                               is_admin_logged_in=is_admin_logged_in, 
                               reviews=reviews)
    
    flash('Produk tidak ditemukan.', 'danger')
    return redirect(url_for('index'))

@app.route('/add_product', methods=['GET', 'POST'])
@admin_required
def add_product():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = float(request.form['price'])
        category = request.form['category'].strip() 
        
        os = request.form.get('os')
        specifications = request.form.get('specifications')
        packages = request.form.get('packages')
        advantages = request.form.get('advantages')
        notes = request.form.get('notes')
        
        image_files = request.files.getlist('images')
        uploaded_image_urls = []

        for img_file in image_files:
            if img_file and img_file.filename != '':
                image_url = upload_single_image_to_imgur(img_file)
                if image_url:
                    uploaded_image_urls.append(image_url)
        
        if not uploaded_image_urls and any(f.filename for f in image_files):
            flash('Gagal mengunggah beberapa atau semua gambar.', 'danger')
            return render_template('admin/add_product.html')

        product_data = {
            'name': name,
            'description': description,
            'price': price,
            'category': category,
            'image_urls': uploaded_image_urls,
            'os': os,
            'specifications': specifications,
            'packages': packages,
            'advantages': advantages,
            'notes': notes
        }
        products_collection.insert_one(product_data)
        flash('Produk berhasil ditambahkan!', 'success')
        return redirect(url_for('index'))
    return render_template('admin/add_product.html')

@app.route('/edit_product/<id>', methods=['GET', 'POST'])
@admin_required
def edit_product(id):
    product = products_collection.find_one({'_id': ObjectId(id)})
    if not product:
        flash('Produk tidak ditemukan.', 'danger')
        return redirect(url_for('index'))
    if 'image_url' in product and not isinstance(product.get('image_urls'), list):
        current_image_urls = [product['image_url']]
    else:
        current_image_urls = product.get('image_urls', [])
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = float(request.form['price'])
        category = request.form['category'].strip()

        os = request.form.get('os')
        specifications = request.form.get('specifications')
        packages = request.form.get('packages')
        advantages = request.form.get('advantages')
        notes = request.form.get('notes')

        kept_image_urls_str = request.form.get('kept_image_urls', '')
        kept_image_urls = [url.strip() for url in kept_image_urls_str.split(',') if url.strip()]
        new_image_files = request.files.getlist('new_images')
        uploaded_new_image_urls = []
        for img_file in new_image_files:
            if img_file and img_file.filename != '':
                image_url = upload_single_image_to_imgur(img_file)
                if image_url:
                    uploaded_new_image_urls.append(image_url)
        final_image_urls = kept_image_urls + uploaded_new_image_urls
        if not final_image_urls:
            flash('Produk harus memiliki setidaknya satu gambar. Tidak ada gambar yang disimpan.', 'danger')
            product['image_urls'] = current_image_urls
            return render_template('admin/edit_product.html', product=product)

        products_collection.update_one(
            {'_id': ObjectId(id)},
            {'$set': {
                'name': name,
                'description': description,
                'price': price,
                'category': category,
                'image_urls': final_image_urls,
                'os': os,
                'specifications': specifications,
                'packages': packages,
                'advantages': advantages,
                'notes': notes
            }}
        )
        flash('Produk berhasil diperbarui!', 'success')
        return redirect(url_for('product_detail', id=id))
    
    product['image_urls'] = current_image_urls
    return render_template('admin/edit_product.html', product=product)

@app.route('/delete_product/<id>', methods=['POST'])
@admin_required
def delete_product(id):
    result = products_collection.delete_one({'_id': ObjectId(id)})
    if result.deleted_count > 0:
        flash('Produk berhasil dihapus!', 'success')
    else:
        flash('Produk tidak ditemukan.', 'danger')
    return redirect(url_for('index'))

@app.route('/submit_review/<product_id>', methods=['POST'])
def submit_review(product_id):
    if not session.get('user_id'):
        flash('Silakan login untuk memberikan ulasan.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    user_name = session['username']

    rating = request.form.get('rating')
    comment = request.form.get('comment')
    
    if not rating or not comment:
        flash('Rating dan komentar wajib diisi.', 'danger')
        return redirect(url_for('product', id=product_id))

    try:
        review_data = {
            'product_id': ObjectId(product_id),
            'user_id': ObjectId(user_id),
            'user_name': user_name,
            'rating': int(rating),
            'comment': comment,
            'created_at': datetime.now()
        }
        reviews_collection.insert_one(review_data)
        
        flash('Ulasan Anda berhasil dikirim!', 'success')
    except Exception as e:
        flash(f'Terjadi kesalahan saat menyimpan ulasan: {e}', 'danger')
        app.logger.error(f"Error submitting review: {e}")

    return redirect(url_for('product_detail', id=product_id))

@app.route('/submit_admin_reply/<review_id>', methods=['POST'])
@admin_required
def submit_admin_reply(review_id):
    admin_reply = request.form.get('admin_reply', '').strip()
    
    if not admin_reply:
        flash('Balasan tidak boleh kosong.', 'danger')
        return redirect(request.referrer or url_for('index'))

    try:
        result = reviews_collection.update_one(
            {'_id': ObjectId(review_id)},
            {'$set': {'admin_reply': admin_reply}}
        )
        if result.modified_count > 0:
            flash('Balasan admin berhasil diperbarui!', 'success')
        else:
            flash('Ulasan tidak ditemukan atau balasan tidak berubah.', 'info')
    except Exception as e:
        flash(f'Terjadi kesalahan saat menyimpan balasan: {e}', 'danger')
        app.logger.error(f"Error submitting admin reply: {e}")

    review = reviews_collection.find_one({'_id': ObjectId(review_id)})
    if review and review.get('product_id'):
        return redirect(url_for('product_detail', id=str(review['product_id'])))
    
    return redirect(url_for('index'))

@app.route('/delete_admin_reply/<review_id>', methods=['POST'])
@admin_required
def delete_admin_reply(review_id):
    try:
        result = reviews_collection.update_one(
            {'_id': ObjectId(review_id)},
            {'$unset': {'admin_reply': ''}}
        )
        if result.modified_count > 0:
            flash('Balasan admin berhasil dihapus!', 'success')
        else:
            flash('Balasan tidak ditemukan.', 'warning')
    except Exception as e:
        flash(f'Terjadi kesalahan saat menghapus balasan: {e}', 'danger')
        app.logger.error(f"Error deleting admin reply: {e}")

    review = reviews_collection.find_one({'_id': ObjectId(review_id)})
    if review and review.get('product_id'):
        return redirect(url_for('product_detail', id=str(review['product_id'])))
    
    return redirect(url_for('index'))

@app.route('/cart', methods=['GET'])
def view_cart():
    cart_items = []
    subtotal_price = 0
    for product_id, item_data in session['cart'].items():
        cart_items.append({
            'id': product_id,
            'name': item_data['name'],
            'price': item_data['price'],
            'quantity': item_data['quantity'],
            'image_url': item_data.get('image_url'),
            'subtotal': item_data['price'] * item_data['quantity']
        })
        subtotal_price += item_data['price'] * item_data['quantity']
    
    total_price = subtotal_price

    return render_template('cart/cart.html', 
                           cart_items=cart_items, 
                           subtotal_price=subtotal_price,
                           total_price=total_price)

@app.route('/add_to_cart/<product_id>', methods=['POST'])
def add_to_cart(product_id):
    product = products_collection.find_one({'_id': ObjectId(product_id)})
    if product:
        product['_id'] = str(product['_id']) 
        
        if product_id in session['cart']:
            session['cart'][product_id]['quantity'] += 1
        else:
            first_image_url = product.get('image_urls', [None])[0] 
            session['cart'][product_id] = {
                'name': product['name'],
                'price': product['price'],
                'image_url': first_image_url,
                'quantity': 1
            }
        session.modified = True
        flash(f'{product["name"]} telah ditambahkan ke keranjang!', 'success')
    else:
        flash('Produk tidak ditemukan.', 'danger')
    return redirect(request.referrer or url_for('index'))

@app.route('/remove_from_cart/<product_id>', methods=['POST'])
def remove_from_cart(product_id):
    if product_id in session['cart']:
        session['cart'][product_id]['quantity'] -= 1
        if session['cart'][product_id]['quantity'] <= 0:
            del session['cart'][product_id]
        session.modified = True
        flash('Item berhasil diperbarui di keranjang.', 'info')
    else:
        flash('Item tidak ditemukan di keranjang.', 'warning')
    return redirect(url_for('view_cart'))

@app.route('/clear_item_from_cart/<product_id>', methods=['POST'])
def clear_item_from_cart(product_id):
    if product_id in session['cart']:
        product_name = session['cart'][product_id]['name']
        del session['cart'][product_id]
        session.modified = True
        flash(f'{product_name} telah dihapus sepenuhnya dari keranjang.', 'info')
    else:
        flash('Item tidak ditemukan di keranjang.', 'warning')
    return redirect(url_for('view_cart'))

@app.route('/checkout_success', methods=['GET'])
@login_required
def checkout_success():
    if 'cart' not in session or not session['cart']:
        flash('Keranjang belanja Anda kosong.', 'danger')
        return redirect(url_for('view_cart'))

    user_id = session.get('user_id')
    user = users_collection.find_one({'_id': ObjectId(user_id)})

    if not user:
        flash('Data pengguna tidak ditemukan.', 'danger')
        return redirect(url_for('login'))
        
    user_email = user.get('email')
    if not user_email:
        flash('Struk pemesanan berhasil terkirim ke email anda.', 'success')
        user_email = user.get('username')
        if not user_email:
            flash('Tidak ada email atau username yang terdaftar. Struk tidak dapat dikirim.', 'warning')
            
    cart_items = session['cart']
    total_price = 0
    items_for_db = []

    for product_id, item_data in cart_items.items():
        item_total = item_data['price'] * item_data['quantity']
        total_price += item_total
        items_for_db.append({
            'product_id': product_id,
            'name': item_data['name'],
            'quantity': item_data['quantity'],
            'price': item_data['price'],
            'subtotal': item_total
        })

    order_data = {
        'user_id': user_id,
        'items': items_for_db,
        'total_price': total_price,
        'date': datetime.now(),
        'status': 'Completed'
    }
    
    new_order = db.orders.insert_one(order_data)
    order_id = new_order.inserted_id

    if user_email:
        send_receipt_email(order_id, user_email)

    session.pop('cart', None)
    session.modified = True
    flash('Pesanan Anda telah berhasil diproses!', 'success')
    
    return redirect(url_for('render_checkout_success', order_id=str(order_id)))

@app.route('/checkout_success_page/<order_id>')
@login_required
def render_checkout_success(order_id):
    return render_template('cart/checkout_success.html', order_id=order_id)

def create_receipt_pdf_data(order_id):
    try:
        try:
            order_id_obj = ObjectId(order_id)
        except Exception:
            print(f"ID pesanan tidak valid: {order_id}")
            return None

        order = db.orders.find_one({'_id': order_id_obj})
        if not order:
            print(f"Pesanan tidak ditemukan: {order_id}")
            return None

        buffer = io.BytesIO()

        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )

        story = []
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name='HeaderStyle',
            fontName='Roboto-Bold',
            fontSize=12,
            alignment=TA_CENTER,
            spaceAfter=12,
            textColor=colors.HexColor("#21c0b3")
        ))
        styles.add(ParagraphStyle(
            name='NormalStyle',
            fontName='Roboto',
            fontSize=12,
            spaceAfter=6,
            textColor=colors.HexColor("#011e36")
        ))
        styles.add(ParagraphStyle(
            name='NormalBold',
            fontName='Roboto-Bold',
            fontSize=12,
            spaceAfter=6,
            textColor=colors.HexColor("#011e36")
        ))
        styles.add(ParagraphStyle(
            name='FooterStyle',
            fontName='Roboto',
            fontSize=12,
            alignment=TA_CENTER,
            spaceAfter=6,
            textColor=colors.HexColor("#011e36")
        ))

        logo_path = os.path.join(basedir, 'logo.png')
        try:
            logo = Image(logo_path, width=3.0 * cm, height=2.0 * cm)
            story.append(logo)
            story.append(Spacer(1, 0.2 * cm))
        except FileNotFoundError:
            pass

        story.append(Paragraph("STRUK PESANAN", styles['HeaderStyle']))
        story.append(Spacer(1, 0.5 * cm))
        story.append(Paragraph(f"<b>Nomor Transaksi:</b> {order_id}", styles['NormalStyle']))

        order_date = order.get('date')
        if isinstance(order_date, datetime):
            story.append(Paragraph(
                f"<b>Tanggal:</b> {order_date.strftime('%d %B %Y %H:%M')}",
                styles['NormalStyle']
            ))
        else:
            story.append(Paragraph("<b>Tanggal:</b> Data tanggal tidak valid", styles['NormalStyle']))
            
        story.append(Spacer(1, 1.0 * cm))

        data_table = [['Produk', 'Kuantitas', 'Harga', 'Subtotal']]
        total_price = order.get('total_price', 0)
        
        for item in order.get('items', []):
            try:
                price = float(item.get('price', 0))
                quantity = int(item.get('quantity', 0))
                subtotal = price * quantity
                data_table.append([
                    Paragraph(item.get('name', 'N/A'), styles['NormalStyle']),
                    str(quantity),
                    f"Rp {price:,.2f}",
                    f"Rp {subtotal:,.2f}"
                ])
            except (ValueError, TypeError) as e:
                print(f"Error memproses item pesanan: {e} - Item: {item}")
                continue
            
        data_table.append(['', '', Paragraph("<b>Total</b>", styles['NormalBold']), Paragraph(f"<b>Rp {total_price:,.2f}</b>", styles['NormalBold'])])

        table = Table(data_table, colWidths=[6 * cm, 2 * cm, 3 * cm, 3 * cm])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F0F0F0')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#000000")),
            ('FONTNAME', (0, 0), (-1, 0), 'Roboto-Bold'),
            ('ALIGN', (1, 0), (-1, -1), 'RIGHT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, -1), (-1, -1), 'Roboto-Bold'),
            ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#DCDCDC')),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(table)
        story.append(Spacer(1, 1.5 * cm))
        story.append(Paragraph("TERIMAKASIH TELAH BERBELANJA!", styles['HeaderStyle']))
        story.append(Spacer(1, 1.0 * cm))
        story.append(Paragraph("Hubungi kami: 6285156069031", styles['FooterStyle']))
        story.append(Paragraph("Alamat: jl.kesana-kesini, kp.apa, kec.itu", styles['FooterStyle']))

        doc.build(story)
        buffer.seek(0)
        
        return buffer.getvalue()
    except Exception as e:
        print(f"ReportLab Error saat membuat struk untuk order ID {order_id}: {e}")
        return None

@app.route('/generate-receipt/<order_id>')
@login_required
def generate_receipt(order_id):
    receipt_data = create_receipt_pdf_data(order_id)
    if receipt_data:
        return send_file(
            io.BytesIO(receipt_data),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"struk_pembelian_{order_id}.pdf"
        )
    else:
        flash('Terjadi kesalahan saat membuat struk. Silakan coba lagi atau hubungi dukungan.', 'danger')
        return redirect(url_for('render_checkout_success', order_id=order_id))
    
@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/terms-and-conditions')
def terms_and_conditions():
    return render_template('terms_and_conditions.html')

@app.route('/sitemap.xml', methods=['GET'])
def sitemap():
    base_url = get_base_url()

    static_urls = [
        {'loc': url_for('index', _external=True), 'lastmod': datetime.now().isoformat(), 'changefreq': 'daily', 'priority': '1.0'},
        {'loc': url_for('login', _external=True), 'lastmod': datetime.now().isoformat(), 'changefreq': 'monthly', 'priority': '0.8'},
        {'loc': url_for('register', _external=True), 'lastmod': datetime.now().isoformat(), 'changefreq': 'monthly', 'priority': '0.8'},
        {'loc': url_for('view_cart', _external=True), 'lastmod': datetime.now().isoformat(), 'changefreq': 'weekly', 'priority': '0.6'},
        {'loc': url_for('privacy_policy', _external=True), 'lastmod': datetime.now().isoformat(), 'changefreq': 'monthly', 'priority': '0.5'},
        {'loc': url_for('terms_and_conditions', _external=True), 'lastmod': datetime.now().isoformat(), 'changefreq': 'monthly', 'priority': '0.5'},
        {'loc': url_for('forgot_password', _external=True), 'lastmod': datetime.now().isoformat(), 'changefreq': 'monthly', 'priority': '0.4'},
    ]

    product_urls = []
    try:
        products = products_collection.find({}, {'_id': 1, 'updated_at': 1})
        for product in products:
            lastmod = product.get('updated_at', datetime.now()).isoformat()
            product_urls.append({
                'loc': url_for('product_detail', id=str(product['_id']), _external=True),
                'lastmod': lastmod,
                'changefreq': 'weekly',
                'priority': '0.9'
            })
    except Exception as e:
        print(f"Error fetching products for sitemap: {e}")

    urls = static_urls + product_urls

    xml_content = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml_content += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    for url_data in urls:
        xml_content += '  <url>\n'
        xml_content += f'    <loc>{url_data["loc"]}</loc>\n'
        if 'lastmod' in url_data:
            xml_content += f'    <lastmod>{url_data["lastmod"]}</lastmod>\n'
        if 'changefreq' in url_data:
            xml_content += f'    <changefreq>{url_data["changefreq"]}</changefreq>\n'
        if 'priority' in url_data:
            xml_content += f'    <priority>{url_data["priority"]}</priority>\n'
        xml_content += '  </url>\n'
    xml_content += '</urlset>\n'

    return Response(xml_content, mimetype='application/xml')

@app.route('/robots.txt', methods=['GET'])
def robots_txt():
    base_url = get_base_url()

    robots_content = f"""User-agent: *
Allow: /
Sitemap: {base_url}/sitemap.xml
"""
    return Response(robots_content, mimetype='text/plain')