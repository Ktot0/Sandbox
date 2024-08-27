document.addEventListener('DOMContentLoaded', (event) => {
    const reportName = "{{ report_name | e('js') }}"; // URL encoding in JavaScript context

    fetch(`/reports/${reportName}/files`)
        .then(response => response.json())
        .then(data => {
            if (data.files) {
                const tabContainer = document.createElement('div');
                tabContainer.className = 'tab';
                const tabContentContainer = document.getElementById('dynamicTabContents');

                data.files.forEach(file => {
                    const moduleName = file.split('-')[0];
                    if (!moduleName.includes("core")) {  // Check for "core" in the module name
                        const tabButton = document.createElement('button');
                        tabButton.className = 'tablinks';
                        tabButton.textContent = moduleName;
                        tabButton.onclick = (event) => openTab(event, moduleName);
                        tabContainer.appendChild(tabButton);

                        const tabContent = document.createElement('div');
                        tabContent.id = moduleName;
                        tabContent.className = 'tabcontent';
                        tabContentContainer.appendChild(tabContent);

                        fetch(`/reports/${reportName}/${file}`)
                            .then(response => response.text())
                            .then(htmlContent => {
                                tabContent.innerHTML = htmlContent;
                            });
                    }
                });

                // Add dynamic tabs to the tab container
                document.getElementById('staticTabs').appendChild(tabContainer);

                // Open the first tab by default
                if (document.querySelectorAll('.tablinks').length > 0) {
                    document.querySelectorAll('.tablinks')[0].click();
                }
            }
        });
});

function openTab(evt, tabName) {
    var i, tabcontent, tablinks;
    tabcontent = document.getElementsByClassName("tabcontent");
    for (i = 0; i < tabcontent.length; i++) {
        tabcontent[i].style.display = "none";
    }
    tablinks = document.getElementsByClassName("tablinks");
    for (i = 0; i < tablinks.length; i++) {
        tablinks[i].className = tablinks[i].className.replace(" active", "");
    }
    document.getElementById(tabName).style.display = "block";
    evt.currentTarget.className += " active";
}
