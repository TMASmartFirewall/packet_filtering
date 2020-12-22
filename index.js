const express = require('express');
const app     = express();

const PORT = 8080;
const staticFileMiddleware = express.static('dist');
app.use(staticFileMiddleware);




app.listen(PORT,() => {
  console.log(`Listening on Port: ${PORT}`)
})
