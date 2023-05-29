// controllers/recipeController.js
const Recipe = require('../models/recipe');

exports.createRecipe = async (req, res) => {
  try {
    const { title, ingredients, steps, image } = req.body;
    const recipe = new Recipe({
      title,
      ingredients,
      steps,
      image,
      user: req.cookies.token.id
    });
    await recipe.save();
    res.status(201).json(recipe);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
};

exports.getRecipes = async (req, res) => {
  try {
    const recipes = await Recipe.find({ user: req.cookies.token.id });
    res.json(recipes);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

exports.getRecipe = async (req, res) => {
  try {
    const recipe = await Recipe.findOne({
      _id: req.params.id,
      user: req.cookies.token.id
    });
    if (!recipe) throw new Error('Recipe not found');
    res.json(recipe);
  } catch (err) {
    res.status(404).json({ message: err.message });
  }
};

exports.updateRecipe = async (req, res) => {
  try {
    const { title, ingredients, steps, image } = req.body;
    const recipe = await Recipe.findOneAndUpdate(
      { _id: req.params.id, user: req.cookies.token.id },
      { title, ingredients, steps, image },
      { new: true }
    );
    if (!recipe) throw new Error('Recipe not found');
    res.json(recipe);
  } catch (err) {
    res.status(404).json({ message: err.message });
  }
};

exports.deleteRecipe = async (req, res) => {
  try {
    const recipe = await Recipe.findOneAndDelete({
      _id: req.params.id,
      user: req.cookies.token.id
    });
    if (!recipe) throw new Error('Recipe not found');
    res.json({ message: 'Recipe deleted' });
  } catch (err) {
    res.status(404).json({ message: err.message });
  }
};
