const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

// =================================================================
// 1. НАСТРОЙКА ШАБЛОНИЗАТОРА И MIDDLEWARE
// =================================================================
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

//парсинг данных из HTML-форм
app.use(express.urlencoded({ extended: true }));

//настройка сессий
app.use(session({
  secret: 'my_super_secret_key_123',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 3600000 } // 1 час
}));

// =================================================================
// 2. ХРАНИЛИЩЕ ПОЛЬЗОВАТЕЛЕЙ (users.json)
// =================================================================
const USERS_FILE = path.join(__dirname, 'users.json');

//загрузить пользователей из файла
function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, '[]');
    return [];
  }
  const data = fs.readFileSync(USERS_FILE, 'utf-8');
  return JSON.parse(data);
}

//сохранить пользователей в файл
function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

let users = loadUsers();

// =================================================================
// 3. MIDDLEWARE ДЛЯ ПРОВЕРКИ АВТОРИЗАЦИИ И ПРАВ
// =================================================================
function requireAuth(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  res.redirect('/login');
}

//проверка прав администратора
function requireAdmin(req, res, next) {
  if (req.session && req.session.user && req.session.user.role === 'admin') {
    return next();
  }
  res.status(403).send('403 Forbidden: доступ только для администратора');
}

// =================================================================
// 4. МАРШРУТЫ
// =================================================================

//главная
app.get('/', (req, res) => {
  const currentUser = req.session.user || null;
  res.render('index', { user: currentUser });
});

//форма регистрации
app.get('/register', (req, res) => {
  if (req.session.user) {
    return res.redirect('/');
  }
  res.render('register', { error: null });
});

//обработка регистрации
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.render('register', { error: 'Заполните все поля!' });
  }

  if (password.length < 6) {
    return res.render('register', { error: 'Пароль должен содержать минимум 6 символов!' });
  }

  const existingUser = users.find(u => u.username === username);
  if (existingUser) {
    return res.render('register', { error: 'Пользователь с таким именем уже существует!' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const role = users.length === 0 ? 'admin' : 'user';

  const newUser = {
    id: Date.now(),
    username: username,
    password: hashedPassword,
    role: role
  };
  users.push(newUser);
  saveUsers(users);

  req.session.user = {
    id: newUser.id,
    username: newUser.username,
    role: newUser.role
  };
  res.redirect('/');
});

//форма входа
app.get('/login', (req, res) => {
  if (req.session.user) {
    return res.redirect('/');
  }
  res.render('login', { error: null });
});

//обработка входа
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.render('login', { error: 'Заполните все поля!' });
  }

  const user = users.find(u => u.username === username);
  if (!user) {
    return res.render('login', { error: 'Неверное имя пользователя или пароль!' });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.render('login', { error: 'Неверное имя пользователя или пароль!' });
  }

  req.session.user = {
    id: user.id,
    username: user.username,
    role: user.role
  };
  res.redirect('/');
});

//выход
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Ошибка при завершении сессии:', err);
    }
    res.redirect('/');
  });
});

//личный кабинет
app.get('/dashboard', requireAuth, (req, res) => {
  res.render('dashboard', { user: req.session.user });
});

//админ панель
app.get('/admin', requireAuth, requireAdmin, (req, res) => {
  res.render('admin', {
    user: req.session.user,
    users: users
  });
});

//удаление пользователя (только для админа)
app.post('/admin/delete/:id', requireAuth, requireAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);

  //нельзя удалить самого себя
  if (id === req.session.user.id) {
    return res.status(400).send('Нельзя удалить самого себя');
  }

  users = users.filter(u => u.id !== id);
  saveUsers(users);
  res.redirect('/admin');
});

// =================================================================
// 5. ЗАПУСК СЕРВЕРА
// =================================================================
app.listen(PORT, () => {
  console.log(`Сервер запущен и доступен по адресу: http://localhost:${PORT}`);
});