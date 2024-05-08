const express = require("express");
const path = require("path");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
const dbPath = path.join(__dirname, "userData.db");
let db = null;

const initializeDBAndServer = async () => {
  try {
    db = await open({ filename: dbPath, driver: sqlite3.Database });
    app.listen(3000, () => {
      console.log("Server Running at http://localhost:3000");
    });
  } catch (e) {
    console.log(`DBError: ${e.message}`);
    process.exit(1);
  }
};

initializeDBAndServer();

const authenticateToken = (request, response, next) => {
  const authHeader = request.headers["authorization"];
  let jwtToken;
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(" ")[1];
  }
  if (jwtToken === undefined) {
    response.status(401);
    response.send("Invalid Access Token");
  } else {
    jwt.verify(jwtToken, "MY_SECRET_TOKEN_JVV", async (error, payload) => {
      if (error) {
        response.status(401);
        response.send("Invalid Access Token");
      } else {
        request.username = payload.username;
        next();
      }
    });
  }
};

// Register A New User API

app.post("/register/", async (request, response) => {
  const { username, name, password, gender, location } = request.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const selectUserQuery = `
        SELECT * FROM user WHERE username = '${username}';
    `;
  const getUsernameDetails = await db.get(selectUserQuery);
  if (getUsernameDetails === undefined) {
    if (password.length < 6) {
      response.status(400);
      response.send("Password is too short");
    } else {
      const createUserQuery = `
                INSERT INTO user(username, name, password, gender, location)
                VALUES(
                    '${username}',
                    '${name}',
                    '${hashedPassword}',
                    '${gender}',
                    '${location}'
                );
            `;
      await db.run(createUserQuery);
      response.send("User created successfully");
    }
  } else {
    response.status(400);
    response.send("User already exists");
  }
});

// Login User API

app.post("/login/", async (request, response) => {
  const { username, password } = request.body;
  const selectUserQuery = `
        SELECT * FROM user WHERE username = '${username}';
    `;
  const getSelectUserDetails = await db.get(selectUserQuery);
  if (getSelectUserDetails === undefined) {
    response.status(400);
    response.send("Invalid user");
  } else {
    const isPasswordMatched = await bcrypt.compare(
      password,
      getSelectUserDetails.password
    );
    if (isPasswordMatched === true) {
      const payload = {
        username: username,
      };
      const jwtToken = jwt.sign(payload, "MY_SECRET_TOKEN_JVV");
      response.send({ jwtToken });
    } else {
      response.status(400);
      response.send("Invalid password");
    }
  }
});

// Retrieve User Details

app.get("/profile/", authenticateToken, async (request, response) => {
  const username = request.username;
  const profileDetailsQuery = `
        SELECT *
        FROM user
        WHERE username='${username}';
    `;
  const dbUser = await db.get(profileDetailsQuery);
  response.send(dbUser);
});

// Update Password API

app.put("/change-password/", authenticateToken, async (request, response) => {
  const { username, oldPassword, newPassword } = request.body;
  const selectUserQuery = `
    SELECT * FROM user WHERE username = '${username}';
  `;
  const getSelectDetails = await db.get(selectUserQuery);
  //   console.log(getSelectDetails.password);

  const isOldPasswordMAtched = await bcrypt.compare(
    oldPassword,
    getSelectDetails.password
  );
  if (isOldPasswordMAtched === true) {
    if (newPassword.length < 6) {
      response.status(400);
      response.send("Password is too short");
    } else {
      const hashedNewPassword = await bcrypt.hash(newPassword, 10);
      const updatePasswordQuery = `
                UPDATE user 
                SET password = '${hashedNewPassword}'
                WHERE username = '${username}';
            `;
      await db.run(updatePasswordQuery);
      response.send("Password updated");
    }
  } else {
    response.status(400);
    response.send("Invalid current password");
  }
});

// Delete a User

app.delete("/delete/", authenticateToken, async (request, response) => {
  const { username } = request.body;
  const deleteQuery = `
        DELETE FROM user WHERE username = '${username}';
    `;
  await db.run(deleteQuery);
  response.send("User Deleted Successfully!");
});

// Get All Users Data

app.get("/", authenticateToken, async (request, response) => {
  const selectUsersQueryAll = `
          SELECT * FROM user;
      `;
  const responseData = await db.all(selectUsersQueryAll);
  response.send(responseData);
});

module.exports = app;
