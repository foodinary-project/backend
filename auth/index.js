const Hapi = require("@hapi/hapi");
const Joi = require("joi");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const users = [];
const JWT_SECRET = "your_jwt_secret";

const validateUser = (username, password) => {
  const user = users.find((u) => u.username === username);
  if (!user) return false;
  return bcrypt.compareSync(password, user.password);
};

const init = async () => {
  const server = Hapi.server({
    port: 3000,
    host: "localhost",
  });

  server.route({
    method: "GET",
    path: "/",
    handler: (request, h) => {
      return { message: "Welcome to the Authentication API" };
    },
  });

  server.route({
    method: "POST",
    path: "/register",
    options: {
      validate: {
        payload: Joi.object({
          username: Joi.string().min(4).required(),
          password: Joi.string()
            .min(8)
            .pattern(new RegExp("^(?=.*[A-Z])(?=.*\\d).+$"))
            .required()
            .messages({
              "string.pattern.base":
                "Password must contain at least one uppercase letter and one number",
            }),
          confirmPassword: Joi.string()
            .valid(Joi.ref("password"))
            .required()
            .messages({
              "any.only": "Password confirmation does not match password",
            }),
        }),
        failAction: (request, h, err) => {
          return h
            .response({
              statusCode: 400,
              message: err.details[0].message,
            })
            .code(400)
            .takeover();
        },
      },
    },
    handler: (request, h) => {
      const { username, password } = request.payload;
      if (users.find((u) => u.username === username)) {
        return h
          .response({
            statusCode: 400,
            message: "Username already exists",
          })
          .code(400);
      }
      const hashedPassword = bcrypt.hashSync(password, 10);
      users.push({ username, password: hashedPassword });
      return {
        statusCode: 201,
        message: "Username registered successfully",
      };
    },
  });

  server.route({
    method: "POST",
    path: "/login",
    options: {
      validate: {
        payload: Joi.object({
          username: Joi.string().required(),
          password: Joi.string().required(),
        }),
      },
    },
    handler: (request, h) => {
      const { username, password } = request.payload;
      const user = users.find((u) => u.username === username);
      if (!user || !bcrypt.compareSync(password, user.password)) {
        return h
          .response({
            statusCode: 401,
            message: "Invalid username or password",
          })
          .code(401);
      }
      const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "1h" });
      return {
        token: token,
        message: "Login successfully",
      };
    },
  });

  server.route({
    method: "POST",
    path: "/reset-password",
    options: {
      validate: {
        payload: Joi.object({
          username: Joi.string().required(),
          oldPassword: Joi.string().required(),
          newPassword: Joi.string()
            .min(8)
            .pattern(new RegExp("^(?=.*[A-Z])(?=.*\\d).+$"))
            .required()
            .messages({
              "string.pattern.base":
                "Password must contain at least one uppercase letter and one number",
            }),
        }),
        failAction: (request, h, err) => {
          return h
            .response({
              statusCode: 400,
              message: err.details[0].message,
            })
            .code(400)
            .takeover();
        },
      },
    },
    handler: (request, h) => {
      const { username, oldPassword, newPassword } = request.payload;
      const user = users.find((u) => u.username === username);
      if (!user) {
        return h.response({ message: "Username not found" }).code(404);
      }
      if (!bcrypt.compareSync(oldPassword, user.password)) {
        return h.response({ message: "Old password is incorrect" }).code(401);
      }
      user.password = bcrypt.hashSync(newPassword, 10);
      return { message: "Password reset successfully" };
    },
  });

  server.route({
    method: "PUT",
    path: "/update-profile",
    options: {
      validate: {
        payload: Joi.object({
          username: Joi.string().min(4).required(),
          newUsername: Joi.string().min(4),
          newPassword: Joi.string()
            .min(8)
            .pattern(new RegExp("^(?=.*[A-Z])(?=.*\\d).+$"))
            .messages({
              "string.pattern.base":
                "Password must contain at least one uppercase letter and one number",
            }),
        }),
        failAction: (request, h, err) => {
          return h
            .response({
              statusCode: 400,
              message: err.details[0].message,
            })
            .code(400)
            .takeover();
        },
      },
    },
    handler: (request, h) => {
      const { username, newUsername, newPassword } = request.payload;
      const user = users.find((u) => u.username === username);
      if (!user) {
        return h
          .response({ statusCode: 404, message: "User not found" })
          .code(404);
      }
      if (newUsername) {
        if (users.find((u) => u.username === newUsername)) {
          return h
            .response({
              statusCode: 400,
              message: "New username already exists",
            })
            .code(400);
        }
        user.username = newUsername;
      }
      if (newPassword) {
        user.password = bcrypt.hashSync(newPassword, 10);
      }
      return {
        statusCode: 200,
        message: "Profile updated successfully",
        user: { username: user.username },
      };
    },
  });

  await server.start();
  console.log("Server running on %s", server.info.uri);
};

process.on("unhandledRejection", (err) => {
  console.log(err);
  process.exit(1);
});

init();
