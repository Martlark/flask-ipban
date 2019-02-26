class View {
    constructor() {
        this.pageNotFoundCount = 0;
    }

    static setMessage(message) {
        document.getElementById('message').innerText = message;
    }

    banMe(ban_count) {
        for (let x = 0; x <= ban_count; x++) {
            fetch('/does_not_exist').then(response => {
                switch (response.status) {
                    case 403:
                        View.setMessage("Forbidden: I've been banned");
                        break;
                    case 404:
                        this.pageNotFoundCount++;
                        View.setMessage("Page not found");
                        break;
                    default:
                        View.setMessage(`Unexpected status ${response.status}`);
                        break;
                }
            }).catch(err => {
                View.setMessage(`Error: ${err}`);
            })
        }
    }

    ignoreTest(ban_count) {
        for (let x = 0; x <= ban_count; x++) {
            const random_int = parseInt(Math.random() * 999999);
            fetch(`/tmp/${random_int}`).then(response => {
                switch (response.status) {
                    case 403:
                        View.setMessage("Forbidden: I've been banned");
                        break;
                    case 404:
                        this.pageNotFoundCount++;
                        View.setMessage(`Page not found: count ${this.pageNotFoundCount}`);
                        break;
                    default:
                        View.setMessage(`Unexpected status ${response.status}`);
                        break;
                }
            }).catch(err => {
                View.setMessage(`Error: ${err}`);
            })
        }
    }

    addToBan(ip) {
        fetch(`/block_it/${ip}`).then(response => {
            switch (response.status) {
                case 200:
                    View.setMessage("Added to ban list");
                    break;
                case 403:
                    View.setMessage("Forbidden");
                    break;
                default:
                    View.setMessage(`Unexpected status ${response.status}`);
                    break;
            }
        }).catch(err => {
            View.setMessage(`Error: ${err}`);
        })
    }

    getIndex() {
        fetch(`/`).then(response => View.setMessage(`get / Status ${response.status}`)
        ).catch(err => {
            View.setMessage(`Error: ${err}`);
        })
    }

    addIt() {
        fetch(`/add_it`).then(response => {
            switch (response.status) {
                case 200:
                    response.text().then(value => View.setMessage(value));
                    break;
                case 403:
                    View.setMessage("Forbidden");
                    break;
                default:
                    View.setMessage(`Unexpected status ${response.status}`);
                    break;
            }
        }).catch(err => {
            View.setMessage(`Error: ${err}`);
        })
    }

    whiteListAdd(ip) {
        fetch(`/whitelist/${ip}`, {method: "PUT"}).then(response => {
            switch (response.status) {
                case 200:
                    response.text().then(value => View.setMessage(value));
                    break;
                default:
                    View.setMessage(`Unexpected status ${response.status}`);
                    break;
            }
        }).catch(err => {
            View.setMessage(`Error: ${err}`);
        })
    }

    whiteListRemove(ip) {
        fetch(`/whitelist/${ip}`, {method: "DELETE"}).then(response => {
            switch (response.status) {
                case 200:
                    response.text().then(value => View.setMessage(value));
                    break;
                default:
                    View.setMessage(`Unexpected status ${response.status}`);
                    break;
            }
        }).catch(err => {
            View.setMessage(`Error: ${err}`);
        })
    }
}

const controller = new View();
