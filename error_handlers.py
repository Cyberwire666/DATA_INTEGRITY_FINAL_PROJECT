from flask import render_template, flash, redirect, url_for
from mysql.connector import Error as MySQLError
from werkzeug.exceptions import HTTPException
import traceback

def init_error_handlers(app):
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('error.html', error_code=404), 404

    @app.errorhandler(403)
    def forbidden_error(error):
        return render_template('error.html', error_code=403), 403

    @app.errorhandler(500)
    def internal_error(error):
        return render_template('error.html', error_code=500), 500

    @app.errorhandler(MySQLError)
    def handle_mysql_error(error):
        error_message = str(error)
        
        # Handle specific MySQL errors
        if "Duplicate entry" in error_message:
            if "username" in error_message.lower():
                flash("This username is already taken. Please choose a different one.", "danger")
                return redirect(url_for('register'))
            elif "email" in error_message.lower():
                flash("This email is already registered. Please use a different email.", "danger")
                return redirect(url_for('register'))
            else:
                flash("A record with these details already exists.", "danger")
                return redirect(url_for('home'))
        
        elif "Cannot add or update a child row" in error_message:
            flash("Invalid reference data. Please check your input.", "danger")
            return redirect(url_for('home'))
        
        elif "Access denied" in error_message:
            flash("Database access error. Please contact support.", "danger")
            return redirect(url_for('home'))
        
        else:
            # Log the error for debugging
            app.logger.error(f"MySQL Error: {error_message}")
            app.logger.error(traceback.format_exc())
            flash("A database error occurred. Please try again later.", "danger")
            return redirect(url_for('home'))

    @app.errorhandler(Exception)
    def handle_generic_error(error):
        # Log the error for debugging
        app.logger.error(f"Unhandled Error: {str(error)}")
        app.logger.error(traceback.format_exc())
        
        if isinstance(error, HTTPException):
            return error
        
        flash("An unexpected error occurred. Please try again later.", "danger")
        return redirect(url_for('home')) 