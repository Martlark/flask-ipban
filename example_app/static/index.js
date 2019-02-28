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
                View.showResult(response)
            }).catch(err => {
                View.setMessage(`Error: ${err}`);
            })
        }
    }

    ignoreTest(ban_count) {
        for (let x = 0; x <= ban_count; x++) {
            const random_int = parseInt(Math.random() * 999999);
            fetch(`/tmp/${random_int}`).then(response => {
                View.showResult(response)
            }).catch(err => {
                View.setMessage(`Error: ${err}`);
            })
        }
    }

    addToBan(ip) {
        fetch(`/block_it/${ip}`).then(response => {
            View.showResult(response)
        }).catch(err => {
            View.setMessage(`Error: ${err}`);
        })
    }

    getIndex(pageUrl='/hello') {
        fetch(pageUrl).then(response => View.showResult(response)
        ).catch(err => {
            View.setMessage(`Error: ${err}`);
        })
    }

    addIt() {
        fetch(`/add_it`).then(response => {
            this.showResult(response);
        }).catch(err => {
            View.setMessage(`Error: ${err}`);
        })
    }

    static showResult(response) {
        switch (response.status) {
            case 200:
                response.text().then(value => View.setMessage(`${response.status} - ${value}`));
                break;
            case 403:
                View.setMessage(`${response.status} - Forbidden`);
                break;
            case 404:
                View.setMessage(`${response.status} - Page not found`);
                break;
            default:
                View.setMessage(`${response.status} - Unexpected status`);
                break;
        }
    }

    whiteListAdd(ip) {
        fetch(`/whitelist/${ip}`, {method: "PUT"}).then(response => {
            View.showResult(response)
        }).catch(err => {
            View.setMessage(`Error: ${err}`);
        })
    }

    whiteListRemove(ip) {
        fetch(`/whitelist/${ip}`, {method: "DELETE"}).then(response => {
            View.showResult(response)
        }).catch(err => {
            View.setMessage(`Error: ${err}`);
        })
    }
}

const controller = new View();
