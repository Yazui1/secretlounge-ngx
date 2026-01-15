from secretlounge_ng.telegram import TMessage
import tensorflow as tf
import numpy as np
from PIL import Image
import io
import logging
from enum import Enum


class FilterAction(Enum):
    """Enum to specify the action to take for a message."""
    ALLOW = "allow"      # Allow the message through normally
    QUESTION = "question"  # Ask user for confirmation before sending
    BLOCK = "block"      # Block the message completely


# Load the TensorFlow model once at module level
try:
    model = tf.keras.models.load_model("anime_real_model2.keras")
    logging.info("Successfully loaded model")
except Exception as e:
    model = None
    logging.error("Failed to load model: %s", e)


def preprocess_image(img):
    """
    Preprocess an image for model prediction.

    Args:
        img: PIL Image object

    Returns:
        Preprocessed numpy array ready for model.predict()
    """
    img = img.convert("RGB").resize((224, 224))
    arr = np.array(img, dtype=np.float32) / 255.0
    arr = np.expand_dims(arr, axis=0)  # shape (1, 224, 224, 3)
    return arr


def classify_image(photo_file_bytes):
    """
    Classify an image using the loaded TensorFlow model.

    Args:
        photo_file_bytes: Raw image bytes

    Returns:
        FilterAction indicating what to do with the message
    """
    if model is None:
        # If model failed to load, allow messages through
        return FilterAction.ALLOW

    try:
        # Load image from bytes without writing to filesystem
        img = Image.open(io.BytesIO(photo_file_bytes))

        # Preprocess the image
        img_arr = preprocess_image(img)

        # Get prediction
        pred = model.predict(img_arr, verbose=0)[0][0]

        # Decision thresholds:
        if pred > 0.98:
            logging.info(
                "Image blocked by classifier (prediction: %.4f)", pred)
            return FilterAction.BLOCK
        elif pred > 0.93:
            logging.info(
                "Image flagged for confirmation by classifier (prediction: %.4f)", pred)
            return FilterAction.QUESTION
        else:
            return FilterAction.ALLOW

    except Exception as e:
        logging.error("Error classifying image: %s", e)
        # On error, allow the message through
        return FilterAction.ALLOW


def message_filter(user, is_media=False, signed=False, tripcode=False, message: TMessage = None):
    """
    Filter function to control which messages are forwarded.

    Args:
        user: User object with properties like karma, warnings, etc.
        is_media: True if message contains media (photos, videos, documents, etc.)
        signed: True if message is signed with /sign
        tripcode: True if message uses a tripcode
        message: Telegram message object with content, text, caption, etc. (may be None)

    Returns:
        FilterAction enum: ALLOW, BLOCK, or QUESTION
        - ALLOW: Message is sent normally
        - BLOCK: Message is blocked completely
        - QUESTION: User must confirm; if confirmed, message is sent with a vote button
    """

    # Classify images using TensorFlow model
    if message and message.content_type == "photo" and model is not None:
        try:
            # Import bot instance to download photo
            from secretlounge_ng.telegram import bot

            # Get the smallest photo version
            photo = message.photo[0]

            # Download photo file as bytes (no filesystem caching)
            file_info = bot.get_file(photo.file_id)
            photo_bytes = bot.download_file(file_info.file_path)

            # Classify the image
            action = classify_image(photo_bytes)
            if action != FilterAction.ALLOW:
                logging.info(
                    "Photo from user %s classified as: %s", user.id, action.value)
                return action

        except Exception as e:
            logging.error("Error processing photo for classification: %s", e)
            # On error, allow the message through

    if message and (message.content_type != "text"):
        return FilterAction.QUESTION

    # Allow all other messages
    return FilterAction.ALLOW
