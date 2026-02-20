#include "mainwindow.h"
#include <QTabWidget>
#include <QTableWidget>
#include <QTreeWidget>
#include <QTextEdit>
#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <QFileDialog>
#include <QMessageBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QHeaderView>
#include <QGroupBox>
#include <QLabel>
#include <QStatusBar>
#include <QFileInfo>
#include <QDebug>
#include <QDateTime>
#include <QTimer>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    parser = new PEParser(this);
    QIcon app_icon(":/icons/pe_analyzer.jpg");
    setWindowIcon(app_icon);
    setup_ui();
}

MainWindow::~MainWindow() {}

void MainWindow::setup_ui() {
    setWindowTitle("PE Analyzer");
    resize(1000, 700);

    QMenuBar *menu_bar = new QMenuBar(this);
    QMenu *file_menu = menu_bar->addMenu("&File");
    QAction *open_action = file_menu->addAction("&Open PE File");
    open_action->setShortcut(QKeySequence::Open);
    file_menu->addSeparator();
    QAction *exit_action = file_menu->addAction("E&xit");
    setMenuBar(menu_bar);

    connect(open_action, &QAction::triggered, this, &MainWindow::open_file);
    connect(exit_action, &QAction::triggered, this, &MainWindow::close);

    QWidget *central = new QWidget(this);
    setCentralWidget(central);

    QHBoxLayout *main_layout = new QHBoxLayout(central);
    main_layout->setContentsMargins(5, 5, 5, 5);

    QWidget *left_panel = new QWidget();
    left_panel->setMaximumWidth(250);
    left_panel->setMinimumWidth(200);
    QVBoxLayout *left_layout = new QVBoxLayout(left_panel);
    left_layout->setContentsMargins(0, 0, 0, 0);

    QLabel *nav_label = new QLabel("PE Structure:");
    nav_label->setStyleSheet("font-weight: bold; padding: 5px;");
    left_layout->addWidget(nav_label);

    nav_tree = new QTreeWidget();
    nav_tree->setHeaderHidden(true);
    nav_tree->setIndentation(15);
    left_layout->addWidget(nav_tree);

    QTreeWidgetItem *dos_item = new QTreeWidgetItem(nav_tree);
    dos_item->setText(0, "📄 DOS Header");
    dos_item->setData(0, Qt::UserRole, "dos");

    QTreeWidgetItem *nt_item = new QTreeWidgetItem(nav_tree);
    nt_item->setText(0, "📁 NT Headers");
    nt_item->setData(0, Qt::UserRole, "nt");

    QTreeWidgetItem *file_item = new QTreeWidgetItem(nt_item);
    file_item->setText(0, "  📄 File Header");
    file_item->setData(0, Qt::UserRole, "file");

    QTreeWidgetItem *optional_item = new QTreeWidgetItem(nt_item);
    optional_item->setText(0, "  📄 Optional Header");
    optional_item->setData(0, Qt::UserRole, "optional");

    QTreeWidgetItem *data_dir_item = new QTreeWidgetItem(nt_item);
    data_dir_item->setText(0, "  📁 Data Directories");
    data_dir_item->setData(0, Qt::UserRole, "datadir");

    QTreeWidgetItem *sections_item = new QTreeWidgetItem(nav_tree);
    sections_item->setText(0, "📁 Sections");
    sections_item->setData(0, Qt::UserRole, "sections");

    QTreeWidgetItem *imports_item = new QTreeWidgetItem(nav_tree);
    imports_item->setText(0, "📥 Import Table");
    imports_item->setData(0, Qt::UserRole, "imports");

    QTreeWidgetItem *exports_item = new QTreeWidgetItem(nav_tree);
    exports_item->setText(0, "📤 Export Table");
    exports_item->setData(0, Qt::UserRole, "exports");

    nav_tree->expandAll();

    QWidget *right_panel = new QWidget();
    QVBoxLayout *right_layout = new QVBoxLayout(right_panel);
    right_layout->setContentsMargins(0, 0, 0, 0);

    tab_widget = new QTabWidget();
    right_layout->addWidget(tab_widget, 7);

    QWidget *headers_tab = new QWidget();
    QVBoxLayout *headers_layout = new QVBoxLayout(headers_tab);
    headers_layout->setContentsMargins(5, 5, 5, 5);

    table_widget = new QTableWidget();
    table_widget->setColumnCount(2);
    QStringList headers;
    headers << "Property" << "Value";
    table_widget->setHorizontalHeaderLabels(headers);
    table_widget->horizontalHeader()->setStretchLastSection(true);
    table_widget->verticalHeader()->setVisible(false);
    table_widget->setAlternatingRowColors(true);
    table_widget->setEditTriggers(QAbstractItemView::NoEditTriggers);

    headers_layout->addWidget(table_widget);
    tab_widget->addTab(headers_tab, "Headers");

    QWidget *sections_tab = new QWidget();
    QVBoxLayout *sections_layout = new QVBoxLayout(sections_tab);
    sections_layout->setContentsMargins(5, 5, 5, 5);

    QTableWidget *sections_table = new QTableWidget();
    sections_table->setColumnCount(6);
    QStringList sections_headers;
    sections_headers << "Name" << "Virtual Address" << "Virtual Size"
                     << "Raw Address" << "Raw Size" << "Characteristics";
    sections_table->setHorizontalHeaderLabels(sections_headers);
    sections_table->horizontalHeader()->setStretchLastSection(true);
    sections_table->verticalHeader()->setVisible(false);
    sections_table->setAlternatingRowColors(true);
    sections_layout->addWidget(sections_table);

    tab_widget->addTab(sections_tab, "Sections");

    QWidget *import_tab = new QWidget();
    QVBoxLayout *import_layout = new QVBoxLayout(import_tab);
    import_layout->setContentsMargins(5, 5, 5, 5);

    import_tree = new QTreeWidget();
    import_tree->setHeaderLabel("Imported Libraries and Functions");
    import_tree->setAlternatingRowColors(true);
    import_layout->addWidget(import_tree);

    tab_widget->addTab(import_tab, "Import");

    QWidget *export_tab = new QWidget();
    QVBoxLayout *export_layout = new QVBoxLayout(export_tab);
    export_layout->setContentsMargins(5, 5, 5, 5);

    export_table = new QTableWidget();
    export_table->setColumnCount(3);
    QStringList export_headers;
    export_headers << "Ordinal" << "Name" << "RVA";
    export_table->setHorizontalHeaderLabels(export_headers);
    export_table->horizontalHeader()->setStretchLastSection(true);
    export_table->verticalHeader()->setVisible(false);
    export_table->setAlternatingRowColors(true);
    export_layout->addWidget(export_table);

    tab_widget->addTab(export_tab, "Export");

    text_edit = new QTextEdit();
    text_edit->setReadOnly(true);
    text_edit->setMaximumHeight(150);
    text_edit->setStyleSheet("QTextEdit { background-color: #2b2b2b; color: #ffffff; font-family: Courier; }");
    right_layout->addWidget(text_edit, 3);

    main_layout->addWidget(left_panel);
    main_layout->addWidget(right_panel, 1);

    connect(nav_tree, &QTreeWidget::itemClicked, this, &MainWindow::on_tree_item_clicked);
    connect(import_tree, &QTreeWidget::itemClicked, this, &MainWindow::on_import_item_clicked);

    if (statusBar()) {
        QLabel *status_icon = new QLabel();
        status_icon->setPixmap(style()->standardIcon(QStyle::SP_FileIcon).pixmap(16, 16));
        statusBar()->addPermanentWidget(status_icon);

        QLabel *time_label = new QLabel();
        time_label->setText(QDateTime::currentDateTime().toString("hh:mm:ss"));
        statusBar()->addPermanentWidget(time_label);

        QTimer *timer = new QTimer(this);
        connect(timer, &QTimer::timeout, [time_label]() {
            time_label->setText(QDateTime::currentDateTime().toString("hh:mm:ss"));
        });
        timer->start(1000);

        statusBar()->showMessage("Ready");
    }
}

void MainWindow::open_file() {
    QString file_name = QFileDialog::getOpenFileName(
        this,
        "Open PE File",
        "",
        "Executable files (*.exe *.dll *.sys *.ocx);;All files (*.*)"
        );

    if (file_name.isEmpty()) return;

    if (statusBar()) {
        statusBar()->showMessage("🔍 Parsing file: " + file_name);
    }

    if (parser->parseFile(file_name)) {
        setWindowTitle("PE Analyzer - " + QFileInfo(file_name).fileName());

        QTreeWidgetItem *sections_item = nav_tree->topLevelItem(2);
        sections_item->takeChildren();

        QVector<SECTION_HEADER> sections = parser->getSections();
        for (int i = 0; i < sections.size(); i++) {
            char name[9] = {0};
            memcpy(name, sections[i].name, 8);
            QTreeWidgetItem *section_item = new QTreeWidgetItem(sections_item);
            section_item->setText(0, "  📄 " + QString(name));
            section_item->setData(0, Qt::UserRole, QString("section_%1").arg(i));
        }
        sections_item->setExpanded(true);

        display_dos_header();
        display_imports();
        display_exports();

        if (statusBar()) {
            statusBar()->showMessage("✅ File parsed successfully", 3000);
        }
    } else {
        QMessageBox::critical(this, "Error", parser->getLastError());
        if (statusBar()) {
            statusBar()->showMessage("❌ Parsing failed", 3000);
        }
    }
}

void MainWindow::display_dos_header() {
    DOS_HEADER dos = parser->getDosHeader();

    int row = 0;
    table_widget->setRowCount(19);

    auto add_row = [&](const QString& name, const QString& value) {
        table_widget->setItem(row, 0, new QTableWidgetItem(name));
        table_widget->setItem(row, 1, new QTableWidgetItem(value));
        row++;
    };

    add_row("e_magic (MZ Signature)", QString("0x%1").arg(dos.e_magic, 4, 16, QChar('0')));
    add_row("e_cblp", QString("0x%1").arg(dos.e_cbpl, 4, 16, QChar('0')));
    add_row("e_cp", QString("0x%1").arg(dos.e_cp, 4, 16, QChar('0')));
    add_row("e_crlc", QString("0x%1").arg(dos.e_crlc, 4, 16, QChar('0')));
    add_row("e_cparhdr", QString("0x%1").arg(dos.e_cparhdr, 4, 16, QChar('0')));
    add_row("e_minalloc", QString("0x%1").arg(dos.e_minalloc, 4, 16, QChar('0')));
    add_row("e_maxalloc", QString("0x%1").arg(dos.e_maxalloc, 4, 16, QChar('0')));
    add_row("e_ss", QString("0x%1").arg(dos.e_ss, 4, 16, QChar('0')));
    add_row("e_sp", QString("0x%1").arg(dos.e_sp, 4, 16, QChar('0')));
    add_row("e_csum", QString("0x%1").arg(dos.e_csum, 4, 16, QChar('0')));
    add_row("e_ip", QString("0x%1").arg(dos.e_ip, 4, 16, QChar('0')));
    add_row("e_cs", QString("0x%1").arg(dos.e_cs, 4, 16, QChar('0')));
    add_row("e_lfarlc", QString("0x%1").arg(dos.e_lfarlc, 4, 16, QChar('0')));
    add_row("e_ovno", QString("0x%1").arg(dos.e_ovno, 4, 16, QChar('0')));
    add_row("e_res[0]", QString("0x%1").arg(dos.e_res[0], 4, 16, QChar('0')));
    add_row("e_res[1]", QString("0x%1").arg(dos.e_res[1], 4, 16, QChar('0')));
    add_row("e_res[2]", QString("0x%1").arg(dos.e_res[2], 4, 16, QChar('0')));
    add_row("e_res[3]", QString("0x%1").arg(dos.e_res[3], 4, 16, QChar('0')));
    add_row("e_lfanew", QString("0x%1 (%2)").arg(dos.e_lfanew, 8, 16, QChar('0')).arg(dos.e_lfanew));

    text_edit->clear();
    text_edit->append("DOS HEADER");
    text_edit->append(QString("Signature: 0x%1").arg(dos.e_magic, 4, 16, QChar('0')));
    text_edit->append(QString("PE Header Offset: 0x%1 (%2)").arg(dos.e_lfanew, 8, 16, QChar('0')).arg(dos.e_lfanew));
}

void MainWindow::display_file_header() {
    FILE_HEADER file = parser->getNtHeader().file_header;

    int row = 0;
    table_widget->setRowCount(7);

    auto add_row = [&](const QString& name, const QString& value) {
        table_widget->setItem(row, 0, new QTableWidgetItem(name));
        table_widget->setItem(row, 1, new QTableWidgetItem(value));
        row++;
    };

    add_row("Machine", QString("0x%1 (%2)").arg(file.machine, 4, 16, QChar('0'))
                           .arg(get_machine_type_string(file.machine)));
    add_row("Number of Sections", QString::number(file.number_of_section));
    add_row("Time Date Stamp", QString("0x%1").arg(file.time_date_stamp, 8, 16, QChar('0')));
    add_row("Pointer to Symbol Table", QString("0x%1").arg(file.pointer_to_symbol_table, 8, 16, QChar('0')));
    add_row("Number of Symbols", QString::number(file.number_of_symbols));
    add_row("Size of Optional Header", QString("0x%1 (%2)").arg(file.size_of_optional_header, 4, 16, QChar('0'))
                                           .arg(file.size_of_optional_header));
    add_row("Characteristics", QString("0x%1 (%2)").arg(file.characteristics, 4, 16, QChar('0'))
                                   .arg(get_characteristics_string(file.characteristics)));

    text_edit->clear();
    text_edit->append("=== FILE HEADER ===");
    text_edit->append(QString("Machine: %1").arg(get_machine_type_string(file.machine)));
    text_edit->append(QString("Sections: %1").arg(file.number_of_section));
    text_edit->append(QString("Characteristics: %1").arg(get_characteristics_string(file.characteristics)));
}

void MainWindow::display_optional_header() {
    OPTIONAL_HEADER opt = parser->getNtHeader().optional_header;

    int row = 0;
    table_widget->setRowCount(24);

    auto add_row = [&](const QString& name, const QString& value) {
        table_widget->setItem(row, 0, new QTableWidgetItem(name));
        table_widget->setItem(row, 1, new QTableWidgetItem(value));
        row++;
    };

    add_row("Magic", QString("0x%1").arg(opt.magic, 4, 16, QChar('0')));
    add_row("Linker Version", QString("%1.%2").arg(opt.major_linker_version).arg(opt.minor_linker_version));
    add_row("Size of Code", QString("0x%1").arg(opt.size_of_code, 8, 16, QChar('0')));
    add_row("Size of Initialized Data", QString("0x%1").arg(opt.size_of_initialized_data, 8, 16, QChar('0')));
    add_row("Size of Uninitialized Data", QString("0x%1").arg(opt.size_of_uninitialized_data, 8, 16, QChar('0')));
    add_row("Address of Entry Point", QString("0x%1").arg(opt.addr_of_entry_point, 8, 16, QChar('0')));
    add_row("Base of Code", QString("0x%1").arg(opt.base_of_code, 8, 16, QChar('0')));
    add_row("Base of Data", QString("0x%1").arg(opt.base_of_data, 8, 16, QChar('0')));
    add_row("Image Base", QString("0x%1").arg(opt.image_base, 8, 16, QChar('0')));
    add_row("Section Alignment", QString("0x%1").arg(opt.section_alignment, 8, 16, QChar('0')));
    add_row("File Alignment", QString("0x%1").arg(opt.file_alignment, 8, 16, QChar('0')));
    add_row("Operating System Version", QString("%1.%2").arg(opt.major_operating_system_version)
                                            .arg(opt.minor_operating_system_version));
    add_row("Image Version", QString("%1.%2").arg(opt.major_image_version).arg(opt.minor_image_verison));
    add_row("Subsystem Version", QString("%1.%2").arg(opt.major_subsystem_version).arg(opt.minor_subsystem_version));
    add_row("Win32 Version", QString("0x%1").arg(opt.win32_version_value, 8, 16, QChar('0')));
    add_row("Size of Image", QString("0x%1").arg(opt.size_of_image, 8, 16, QChar('0')));
    add_row("Size of Headers", QString("0x%1").arg(opt.size_of_headers, 8, 16, QChar('0')));
    add_row("Checksum", QString("0x%1").arg(opt.check_sum, 8, 16, QChar('0')));
    add_row("Subsystem", QString("0x%1 (%2)").arg(opt.sub_system, 4, 16, QChar('0'))
                             .arg(get_subsystem_string(opt.sub_system)));
    add_row("DLL Characteristics", QString("0x%1 (%2)").arg(opt.dll_characterstics, 4, 16, QChar('0'))
                                       .arg(get_dll_characteristics_string(opt.dll_characterstics)));
    add_row("Stack Reserve Size", QString("0x%1").arg(opt.size_of_stack_reserve, 8, 16, QChar('0')));
    add_row("Stack Commit Size", QString("0x%1").arg(opt.size_of_stack_commit, 8, 16, QChar('0')));
    add_row("Heap Reserve Size", QString("0x%1").arg(opt.size_of_heap_reserve, 8, 16, QChar('0')));
    add_row("Heap Commit Size", QString("0x%1").arg(opt.size_of_heap_commit, 8, 16, QChar('0')));

    text_edit->clear();
    text_edit->append("=== OPTIONAL HEADER ===");
    text_edit->append(QString("Entry Point: 0x%1").arg(opt.addr_of_entry_point, 8, 16, QChar('0')));
    text_edit->append(QString("Image Base: 0x%1").arg(opt.image_base, 8, 16, QChar('0')));
    text_edit->append(QString("Subsystem: %1").arg(get_subsystem_string(opt.sub_system)));
}

void MainWindow::display_data_directories() {
    NT_HEADERS nt = parser->getNtHeader();

    int numDirs = nt.optional_header.number_of_rva_and_sizes;
    table_widget->setRowCount(numDirs);

    const char* dir_names[] = {
        "Export", "Import", "Resource", "Exception",
        "Security", "Base Reloc", "Debug", "Architecture",
        "Global Ptr", "TLS", "Load Config", "Bound Import",
        "IAT", "Delay Import", "COM Descriptor", "Reserved"
    };

    for (int i = 0; i < numDirs; i++) {
        DATA_DIRECTORY dir = nt.optional_header.data_directory[i];
        QString dir_name = (i < 16) ? dir_names[i] : QString("Directory %1").arg(i);

        QString value;
        if (dir.virtual_addr == 0) {
            value = "Not present";
        } else {
            value = QString("RVA: 0x%1, Size: 0x%2")
            .arg(dir.virtual_addr, 8, 16, QChar('0'))
                .arg(dir.size, 8, 16, QChar('0'));
        }

        table_widget->setItem(i, 0, new QTableWidgetItem(dir_name));
        table_widget->setItem(i, 1, new QTableWidgetItem(value));
    }

    text_edit->clear();
    text_edit->append("DATA DIRECTORIES");
    for (int i = 0; i < numDirs; i++) {
        DATA_DIRECTORY dir = nt.optional_header.data_directory[i];
        if (dir.virtual_addr != 0) {
            QString dir_name = (i < 16) ? dir_names[i] : QString("Directory %1").arg(i);
            text_edit->append(QString("%1: RVA=0x%2, Size=0x%3")
                                  .arg(dir_name)
                                  .arg(dir.virtual_addr, 8, 16, QChar('0'))
                                  .arg(dir.size, 8, 16, QChar('0')));
        }
    }
}

void MainWindow::display_sections() {
    QVector<SECTION_HEADER> sections = parser->getSections();

    QTableWidget *sections_table = qobject_cast<QTableWidget*>(tab_widget->widget(1)->layout()->itemAt(0)->widget());
    sections_table->setRowCount(sections.size());

    for (int i = 0; i < sections.size(); i++) {
        char name[9] = {0};
        memcpy(name, sections[i].name, 8);

        sections_table->setItem(i, 0, new QTableWidgetItem(QString(name)));
        sections_table->setItem(i, 1, new QTableWidgetItem(QString("0x%1").arg(sections[i].virtual_addr, 8, 16, QChar('0'))));
        sections_table->setItem(i, 2, new QTableWidgetItem(QString("0x%1").arg(sections[i].Misc.virtual_size, 8, 16, QChar('0'))));
        sections_table->setItem(i, 3, new QTableWidgetItem(QString("0x%1").arg(sections[i].pointer_to_raw_data, 8, 16, QChar('0'))));
        sections_table->setItem(i, 4, new QTableWidgetItem(QString("0x%1").arg(sections[i].size_of_raw_data, 8, 16, QChar('0'))));
        sections_table->setItem(i, 5, new QTableWidgetItem(QString("0x%1").arg(sections[i].characteristics, 8, 16, QChar('0'))));
    }
    sections_table->resizeColumnsToContents();
}

void MainWindow::display_section_details(int index) {
    QVector<SECTION_HEADER> sections = parser->getSections();
    if (index < 0 || index >= sections.size()) return;

    SECTION_HEADER section = sections[index];
    char name[9] = {0};
    memcpy(name, section.name, 8);

    table_widget->setRowCount(7);

    int row = 0;
    table_widget->setItem(row, 0, new QTableWidgetItem("Name"));
    table_widget->setItem(row, 1, new QTableWidgetItem(QString(name))); row++;

    table_widget->setItem(row, 0, new QTableWidgetItem("Virtual Address"));
    table_widget->setItem(row, 1, new QTableWidgetItem(QString("0x%1").arg(section.virtual_addr, 8, 16, QChar('0')))); row++;

    table_widget->setItem(row, 0, new QTableWidgetItem("Virtual Size"));
    table_widget->setItem(row, 1, new QTableWidgetItem(QString("0x%1").arg(section.Misc.virtual_size, 8, 16, QChar('0')))); row++;

    table_widget->setItem(row, 0, new QTableWidgetItem("Raw Address"));
    table_widget->setItem(row, 1, new QTableWidgetItem(QString("0x%1").arg(section.pointer_to_raw_data, 8, 16, QChar('0')))); row++;

    table_widget->setItem(row, 0, new QTableWidgetItem("Raw Size"));
    table_widget->setItem(row, 1, new QTableWidgetItem(QString("0x%1").arg(section.size_of_raw_data, 8, 16, QChar('0')))); row++;

    table_widget->setItem(row, 0, new QTableWidgetItem("Characteristics"));
    table_widget->setItem(row, 1, new QTableWidgetItem(QString("0x%1").arg(section.characteristics, 8, 16, QChar('0')))); row++;

    table_widget->setItem(row, 0, new QTableWidgetItem("Characteristics (flags)"));
    table_widget->setItem(row, 1, new QTableWidgetItem(get_section_characteristics_string(section.characteristics)));

    text_edit->clear();
    text_edit->append(QString("=== SECTION: %1 ===").arg(name));
    text_edit->append(QString("Virtual Address: 0x%1").arg(section.virtual_addr, 8, 16, QChar('0')));
    text_edit->append(QString("Virtual Size: 0x%1").arg(section.Misc.virtual_size, 8, 16, QChar('0')));
    text_edit->append(QString("Raw Address: 0x%1").arg(section.pointer_to_raw_data, 8, 16, QChar('0')));
    text_edit->append(QString("Raw Size: 0x%1").arg(section.size_of_raw_data, 8, 16, QChar('0')));
    text_edit->append(QString("Characteristics: %1").arg(get_section_characteristics_string(section.characteristics)));
}

void MainWindow::display_imports() {
    import_tree->clear();
    QVector<ImportLibrary> imports = parser->getImports();
    for (const ImportLibrary &lib : imports) {
        QTreeWidgetItem *lib_item = new QTreeWidgetItem(import_tree);
        lib_item->setText(0, lib.name);
        for (const ImportFunction &func : lib.functions) {
            QTreeWidgetItem *func_item = new QTreeWidgetItem(lib_item);
            func_item->setText(0, func.name);
        }
    }
    import_tree->expandAll();
}

void MainWindow::display_exports() {
    QVector<ExportFunction> exports = parser->getExports();
    export_table->setRowCount(exports.size());
    for (int i = 0; i < exports.size(); i++) {
        const ExportFunction &exp = exports[i];
        export_table->setItem(i, 0, new QTableWidgetItem(QString::number(exp.ordinal)));
        export_table->setItem(i, 1, new QTableWidgetItem(exp.name));
        export_table->setItem(i, 2, new QTableWidgetItem(QString("0x%1").arg(exp.rva, 8, 16, QChar('0'))));
    }
    export_table->resizeColumnsToContents();
}

void MainWindow::on_tree_item_clicked(QTreeWidgetItem *item, int column) {
    QString type = item->data(0, Qt::UserRole).toString();
    if (type == "dos") {
        display_dos_header();
    } else if (type == "file") {
        display_file_header();
    } else if (type == "optional") {
        display_optional_header();
    } else if (type == "datadir") {
        display_data_directories();
    } else if (type == "sections") {
        display_sections();
        tab_widget->setCurrentIndex(1);
    } else if (type == "imports") {
        display_imports();
        tab_widget->setCurrentIndex(2);
    } else if (type == "exports") {
        display_exports();
        tab_widget->setCurrentIndex(3);
    } else if (type.startsWith("section_")) {
        int index = type.mid(8).toInt();
        display_section_details(index);
        tab_widget->setCurrentIndex(0);
    }
}

void MainWindow::on_import_item_clicked(QTreeWidgetItem *item, int column) {
    if (item->parent()) {
        QString func_name = item->text(0);
        QString lib_name = item->parent()->text(0);
        text_edit->clear();
        text_edit->append("IMPORT DETAILS");
        text_edit->append(QString("Library: %1").arg(lib_name));
        text_edit->append(QString("Function: %1").arg(func_name));
    }
}

QString MainWindow::get_machine_type_string(uint16_t machine) {
    switch (machine) {
    case 0x014c: return "Intel 386";
    case 0x8664: return "AMD64 (x86-64)";
    case 0x01c0: return "ARM";
    case 0xaa64: return "ARM64";
    case 0x0200: return "IA64";
    default: return QString("Unknown (0x%1)").arg(machine, 4, 16, QChar('0'));
    }
}

QString MainWindow::get_characteristics_string(uint16_t characteristics) {
    QStringList result;
    if (characteristics & 0x0001) result << "RELOCS_STRIPPED";
    if (characteristics & 0x0002) result << "EXECUTABLE_IMAGE";
    if (characteristics & 0x2000) result << "DLL";
    if (characteristics & 0x4000) result << "SYSTEM";
    return result.join(" | ");
}

QString MainWindow::get_section_characteristics_string(uint32_t characteristics) {
    QStringList result;
    if (characteristics & 0x00000020) result << "CODE";
    if (characteristics & 0x00000040) result << "INITIALIZED_DATA";
    if (characteristics & 0x00000080) result << "UNINITIALIZED_DATA";
    if (characteristics & 0x20000000) result << "EXECUTE";
    if (characteristics & 0x40000000) result << "READ";
    if (characteristics & 0x80000000) result << "WRITE";
    return result.join(" | ");
}

QString MainWindow::get_subsystem_string(uint16_t subsystem) {
    switch (subsystem) {
    case 1: return "Native";
    case 2: return "Windows GUI";
    case 3: return "Windows CUI";
    case 5: return "OS2 CUI";
    case 7: return "POSIX CUI";
    case 9: return "Windows CE GUI";
    default: return QString("Unknown (%1)").arg(subsystem);
    }
}

QString MainWindow::get_dll_characteristics_string(uint16_t dllChars) {
    QStringList result;
    if (dllChars & 0x0040) result << "DYNAMIC_BASE";
    if (dllChars & 0x0080) result << "FORCE_INTEGRITY";
    if (dllChars & 0x0100) result << "NX_COMPAT";
    if (dllChars & 0x0200) result << "NO_ISOLATION";
    if (dllChars & 0x0400) result << "NO_SEH";
    if (dllChars & 0x0800) result << "NO_BIND";
    if (dllChars & 0x1000) result << "APPCONTAINER";
    if (dllChars & 0x2000) result << "WDM_DRIVER";
    if (dllChars & 0x4000) result << "GUARD_CF";
    if (dllChars & 0x8000) result << "TERMINAL_SERVER_AWARE";
    return result.join(" | ");
}
