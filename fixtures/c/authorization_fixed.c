int is_authorized(int actor);
void delete_user(int user);

void remove_user(int actor, int user) {
    if (is_authorized(actor)) {
        delete_user(user);
    }
}
