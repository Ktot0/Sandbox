document.addEventListener('DOMContentLoaded', () => {
    console.log('Document loaded');  // Debugging line
    var reportName = "{{ report_name }}";  // Define the `reportName` variable for JavaScript
    document.querySelectorAll('.tablinks').forEach(button => {
        console.log('Adding event listener to button:', button);  // Debugging line
        button.addEventListener('click', () => {
            console.log('Button clicked:', button.getAttribute('data-subcategory'));  // Debugging line
            showData(button.getAttribute('data-subcategory'), reportName);
        });
    });
});

function showData(subcategory, reportName) {
    const dataContainer = document.getElementById('dataContainer');
    if (!dataContainer) {
        console.error('Data container element not found');
        return;
    }
    dataContainer.innerHTML = '<p>Loading...</p>';

    const url = `/reports/${reportName}/volatility-report.json`;
    console.log('Fetching data from:', url);  // Debugging line

    fetch(url)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(jsonContent => {
            let tableHTML = '';
            console.log('Received data:', jsonContent);  // Debugging line
            switch(subcategory) {
                case 'windows.pslist.PsList':
                    tableHTML = `
                        <div class="scrollable-table">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Process Name</th>
                                        <th>PID</th>
                                        <th>Creation Time</th>
                                        <th>Parent PID</th>
                                        <th>Threads</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${jsonContent['windows.pslist.PsList'].map(item => `
                                        <tr>
                                            <td>${item['ImageFileName']}</td>
                                            <td>${item['PID']}</td>
                                            <td>${item['CreateTime']}</td>
                                            <td>${item['PPID']}</td>
                                            <td>${item['Threads']}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>`;
                    break;
                case 'windows.pstree.PsTree':
                    tableHTML = `
                        <div class="scrollable-table">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Process Name</th>
                                        <th>PID</th>
                                        <th>Parent PID</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${jsonContent['windows.pstree.PsTree'].map(item => `
                                        <tr>
                                            <td>${item['ImageFileName']}</td>
                                            <td>${item['PID']}</td>
                                            <td>${item['PPID']}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>`;
                    break;
                case 'windows.dlllist.DllList':
                    tableHTML = `
                        <div class="scrollable-table">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Process Name</th>
                                        <th>PID</th>
                                        <th>Base</th>
                                        <th>Size</th>
                                        <th>DLL</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${jsonContent['windows.dlllist.DllList'].map(item => `
                                        <tr>
                                            <td>${item['ImageFileName']}</td>
                                            <td>${item['PID']}</td>
                                            <td>${item['Base']}</td>
                                            <td>${item['Size']}</td>
                                            <td>${item['FullDllName']}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>`;
                    break;
                case 'windows.handles.Handles':
                    tableHTML = `
                        <div class="scrollable-table">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Handle</th>
                                        <th>PID</th>
                                        <th>Object Type</th>
                                        <th>Granted Access</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${jsonContent['windows.handles.Handles'].map(item => `
                                        <tr>
                                            <td>${item['HandleValue']}</td>
                                            <td>${item['PID']}</td>
                                            <td>${item['ObjectType']}</td>
                                            <td>${item['GrantedAccess']}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>`;
                    break;
                case 'windows.malfind.Malfind':
                    tableHTML = `
                        <div class="scrollable-table">
                            <table>
                                <thead>
                                    <tr>
                                        <th>PID</th>
                                        <th>Process Name</th>
                                        <th>Address</th>
                                        <th>Protection</th>
                                        <th>Malicious Code</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${jsonContent['windows.malfind.Malfind'].map(item => `
                                        <tr>
                                            <td>${item['PID']}</td>
                                            <td>${item['Process']}</td>
                                            <td>${item['Address']}</td>
                                            <td>${item['Protection']}</td>
                                            <td>${item['Disasm']}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>`;
                    break;
                default:
                    tableHTML = '<p>Unknown subcategory</p>';
                    break;
            }
            dataContainer.innerHTML = tableHTML;
        })
        .catch(error => {
            console.error('Error fetching data:', error);
            dataContainer.innerHTML = `<p>Error loading data: ${error.message}</p>`;
        });
}
