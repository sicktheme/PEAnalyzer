#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTreeWidgetItem>
#include <QStatusBar>
#include <QLabel>
#include "peparser.h"

class QTabWidget;
class QTableWidget;
class QTreeWidget;
class QTextEdit;
class QMenuBar;
class QAction;
class QSplitter;
class QListWidget;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void open_file();
    void on_tree_item_clicked(QTreeWidgetItem *item, int column);
    void on_import_item_clicked(QTreeWidgetItem *item, int column);

private:
    void setup_ui();
    void display_dos_header();
    void display_file_header();
    void display_optional_header();
    void display_data_directories();
    void display_sections();
    void display_section_details(int index);
    void display_imports();
    void display_exports();

    // Вспомогательные функции для форматирования
    QString get_machine_type_string(uint16_t machine);
    QString get_characteristics_string(uint16_t characteristics);
    QString get_section_characteristics_string(uint32_t characteristics);
    QString get_subsystem_string(uint16_t subsystem);
    QString get_dll_characteristics_string(uint16_t dllChars);

    // Основные виджеты
    QSplitter *main_splitter;
    QTreeWidget *nav_tree;        // Дерево навигации слева
    QTabWidget *tab_widget;        // Вкладки справа

    // Виджеты на вкладках
    QTableWidget *table_widget;    // Для отображения структур
    QTreeWidget *import_tree;      // Дерево импорта
    QTableWidget *export_table;    // Таблица экспорта
    QTextEdit *text_edit;          // Текстовое представление

    PEParser *parser;
};

#endif // MAINWINDOW_H
