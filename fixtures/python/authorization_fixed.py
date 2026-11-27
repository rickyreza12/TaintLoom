def remove(actor, user):
    if is_authorized(actor):
        delete_user(user)
