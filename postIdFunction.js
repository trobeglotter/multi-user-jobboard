let postIdGenerator = function () {
    var result = '';
    var characters = 'AB9CD8EF7GH6IJ50K5L3MN2OP1QR0STUVWXYZ';
    for (var i = 0; i < 8; i++) {
        result += characters.charAt(Math.floor(Math.random() * 8));
    }
    return result;
}
let postIdFunction = postIdGenerator();

module.exports = postIdFunction;

