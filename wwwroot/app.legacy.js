// Legacy fallback for older browsers
(function () {
    window.BIOSPHERE_LEGACY_READY = true;
    function setText(id, value) {
        var el = document.getElementById(id);
        if (el) el.textContent = value;
    }

    function renderTable(sensors) {
        var container = document.getElementById('sensorTableContainer');
        if (!container) return;
        if (!sensors || !sensors.length) {
            container.innerHTML = '<p class="placeholder-text">No sensors found.</p>';
            return;
        }

        var html = '<table><thead><tr>' +
            '<th>ID</th><th>Name</th><th>Location</th><th>Type</th>' +
            '<th>Reading</th><th>Unit</th><th>Status</th><th>Last Updated</th>' +
            '</tr></thead><tbody>';

        for (var i = 0; i < sensors.length; i++) {
            var s = sensors[i];
            html += '<tr>' +
                '<td>' + s.id + '</td>' +
                '<td>' + s.name + '</td>' +
                '<td>' + s.location + '</td>' +
                '<td>' + s.type + '</td>' +
                '<td>' + s.lastReading + '</td>' +
                '<td>' + s.unit + '</td>' +
                '<td>' + s.status + '</td>' +
                '<td>' + (s.lastUpdated || '') + '</td>' +
                '</tr>';
        }
        html += '</tbody></table>';
        container.innerHTML = html;
    }

    function updateStory(count) {
        var story = document.getElementById('storyText');
        if (story) story.textContent = 'Legacy mode: loaded ' + count + ' sensors.';
    }

    function loadSensors() {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', '/api/Sensors', true);
        xhr.onreadystatechange = function () {
            if (xhr.readyState !== 4) return;
            if (xhr.status >= 200 && xhr.status < 300) {
                try {
                    var sensors = JSON.parse(xhr.responseText);
                    renderTable(sensors);
                    updateStory(sensors.length);
                    setText('bootStatus', 'Legacy mode active. Data loaded: ' + sensors.length);
                } catch (e) {
                    setText('bootStatus', 'Legacy mode parse error.');
                }
            } else {
                setText('bootStatus', 'Legacy mode failed to load sensors.');
            }
        };
        xhr.send();
    }

    setText('bootStatus', 'Legacy mode: loading data...');
    loadSensors();
})();
