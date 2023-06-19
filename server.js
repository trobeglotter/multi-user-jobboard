const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
let port = 8080;

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());


app.set('view engine', 'ejs');

app.use(express.static(__dirname + '/public'));

app.get('/', (req, res) => {
    res.render('home');
});

const router = require('./routes/routeUserPosts');

app.use(router);

app.listen(port);



