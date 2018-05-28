// Requiring bcrypt for password hashing. Using the bcrypt-nodejs version as the regular bcrypt module
// sometimes causes errors on Windows machines
var bcrypt = require("bcrypt-nodejs");
// Creating our User model
module.exports = function(sequelize, DataTypes) {
  var Customer = sequelize.define("customer", {

   // customer.no -> Auto created by SQL 

   id: {
    autoIncrement: true,
    primaryKey: true,
    type: DataTypes.INTEGER,
   },

   //name of the customer
    name : {
      type: DataTypes.STRING,
      allowNull: false,
      unique : false,

    },

    // The email cannot be null, and must be a proper email before creation
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
      validate: {
        isEmail: true
      }
    },
    // The password cannot be null
    password: {
      type: DataTypes.STRING,
      allowNull: false
    },

    // Address 
    address : {
      type: DataTypes.STRING,
      allowNull: false,
      unique : false,
    },

    //Phone 
    phone : {
      type: DataTypes.INTEGER, 
      allowNull: false,
      unique : true,
      validate:{
        isInt: true
      },

    },
    
    
  },{

    freezeTableName: true, // Model tableName will be the same as the model name
    timestamps: false

  });

//   // Creating a custom method for our User model. This will check if an unhashed password entered by the user can be compared to the hashed password stored in our database
//   Customer.prototype.validPassword = function(password) {
//     return bcrypt.compareSync(password, this.password);
//   };
//   // Hooks are automatic methods that run during various phases of the User Model lifecycle
//   // In this case, before a User is created, we will automatically hash their password
//   Customer.hook("beforeCreate", function(customer) {
//     customer.password = bcrypt.hashSync(customer.password, bcrypt.genSaltSync(10), null);
//   });
   return Customer;
};
