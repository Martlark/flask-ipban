class View {
    constructor() {
        this.pageNotFoundCount = 0;
        this.interval = null;
        this.intervalCount = 0;
        this.ban_seconds = Number(document.getElementsByName("ban_seconds")[0].value);
        this.ban_count = Number(document.getElementsByName("ban_count")[0].value);
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

    ignoreTest(ban_count = 10) {
        for (let x = 0; x <= ban_count; x++) {
            const random_int = parseInt(Math.random() * 999999);
            fetch(`/tmp/${random_int}`).then(response => {
                View.showResult(response)
            }).catch(err => {
                View.setMessage(`Error: ${err}`);
            })
        }
    }

    addToBan(ip = '127.0.0.1') {
        fetch(`/block_it/${ip}`).then(response => {
            View.showResult(response)
        }).catch(err => {
            View.setMessage(`Error: ${err}`);
        })
    }

    getIndex(pageUrl = '/hello') {
        fetch(pageUrl).then(response => View.showResult(response)
        ).catch(err => {
            View.setMessage(`Error: ${err}`);
        })
    }

    addIt() {
        fetch(`/add_it`).then(response => {
            View.showResult(response);
        }).catch(err => {
            View.setMessage(`Error: ${err}`);
        })
    }

    getRandomPositiveInt(maxInt = 10) {
        return Math.floor(Math.random() * maxInt)
    }

    intervalMethod() {
        this.intervalCount++;
        let intervalAction = '';
        switch (this.getRandomPositiveInt(7)) {
            case 0:
                this.getIndex('/manager/html');
                intervalAction = 'bad url';
                break;
            case 1:
                this.getIndex('/hello');
                intervalAction = 'hello';
                break;
            case 2:
                this.getIndex(`/tmp/${this.getRandomPositiveInt(1000)}`);
                intervalAction = '/tmp/random';
                break;
            case 3:
                this.addIt();
                intervalAction = 'addIt to ban';
                break;
            case 4:
                this.addToBan();
                intervalAction = 'block';
                break;
            case 5:
                this.getIndex('/un_block_it/127.0.0.1');
                intervalAction = 'un_block';
                break;
            case 6:
                this.ignoreTest();
                intervalAction = 'ignoreTest';
                break;
        }
        const intervalStatus = document.getElementById('interval_status');
        intervalStatus.textContent = `${this.intervalCount} - ${intervalAction}`;
    }

    intervalStart() {
        if (!this.interval) {
            this.interval = setInterval(() => this.intervalMethod(), 1000 * (this.ban_seconds + 1));
        }
    }

    intervalStop() {
        if (this.interval) {
            clearInterval(this.interval);
            this.interval = null;
        }
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
